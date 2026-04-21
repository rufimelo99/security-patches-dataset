# Enrich performance fix — design

**Data:** 2026-04-21
**Autor:** Sofia Reis
**Status:** Design aprovado, pronto para implementation plan
**Relaciona-se com:** [`2026-04-15-weekly-incremental-update.md`](./2026-04-15-weekly-incremental-update.md) (esta é a concretização da secção 3.5 "Cache de GitHub metadata")

## Contexto

A pipeline mensal de enriquecimento (`scripts/pipeline.py::enrich()`) está a correr na VM `secpulse-monitor` (GCP `secpulse-492015`, us-west1-b) há ~38h com ritmo de **~25 entries/h** e ainda **5,275 entries por processar** de um total de 6,214 (dataset com 118,672 commits, dos quais 112,458 já tinham sido processados em runs anteriores).

Os 3 tokens configurados em `scripts/config/github.json` disponibilizam **15,000 req/h**. Observou-se que apenas **0.4–0.6% desse orçamento está a ser consumido** — ou seja, o rate limit não é o bottleneck.

## Causa raiz

Bug algorítmico O(n²) em `scripts/github_data.py::metadata()`:

```python
for idx, row in commits_list.iterrows():
    chain_ord, chain_datetime = sort_chain(repo, row['chain'])  # fetch de TODA a chain
```

E em `sort_chain()`:
```python
for commit in chain_list:
    gcommit = repo.get_commit(sha=sha.strip())  # 1 request por commit
```

Cada vulnerabilidade tem múltiplas linhas no DataFrame (uma por commit da chain). Para cada linha, `sort_chain()` refaz fetch da chain inteira:

- Vuln com chain de 3 commits → 3 linhas → **9 requests em vez de 3**
- Vuln com chain de 10 commits → 10 linhas → **100 requests em vez de 10**

Combinado com:
- Execução serial (latência de rede 200-800ms por request)
- Secondary rate limits da GitHub (403 Forbidden) que triggerem backoffs internos da PyGithub de ~15 min (observados 30 eventos = 7.7h de sono em 38h)
- Ausência de cache persistente (módulo `scripts/lib/github_cache.py` existe, tem tests, mas nunca é importado)

O resultado é que cada run mensal paga o custo total do zero.

## Objetivo

1. Eliminar O(n²) em `metadata()`/`sort_chain()` → O(n) por vulnerabilidade
2. Ligar o `GithubCache` existente ao pipeline, conforme previsto no plano de 2026-04-15
3. Permitir que o run actual retome naturalmente (já filtra linhas com `files != NULL`)

## Não-objetivos

- Paralelismo entre repos (ganho adicional pequeno depois do cache estar ligado)
- Reescrita do downstream de `github_data.py` para usar dicts em vez de PyGithub `Commit` objects
- Alterar schema do CSV de output ou do dataset final
- Tocar em `github_cache.py` (módulo já bem testado)

## Critério de sucesso

- Testes existentes (incluindo `tests/test_github_cache.py`) passam sem alteração
- Novos tests em `tests/test_commit_fetcher.py` e `tests/test_enrich_integration.py` passam
- Primeiro run pós-fix completa sem backoffs excessivos (< 1h total em backoff); ritmo de entries/h pelo menos 2× superior ao baseline de ~25/h
- Segundo run (com cache populado) faz número de chamadas à API aproximadamente igual ao delta de commits novos

## Arquitetura

Duas camadas de cache, comportando-se como fall-through:

```
cli.py::get_metadata(fin, folder)
  └─► github_data.py::metadata(repo, df, git, config, cache, sha_cache)
        └─► sort_chain(repo, chain, sha_cache)
              └─► commit_fetcher.fetch_commit(repo, sha, git, config, cache, sha_cache)
                    1. sha_cache.get(sha)       # in-memory, vida = 1 run   → O(1), 0 reqs
                    2. cache.get(sha)           # disco, TTL 30d            → ~1ms, 0 reqs
                    3. repo.get_commit(sha)     # fallback via PyGithub     → ~300ms, 1-3 reqs
                       commit.get_comments()    # eager fetch antes de guardar
                       cache.put(sha, extract_commit_data(commit))
                       sha_cache[sha] = commit
```

## Componentes

### Novo: `scripts/lib/commit_fetcher.py` (~60 LOC)

Função `fetch_commit(repo, sha, git, config, *, cache, sha_cache)`:
- Unifica a lógica das 3 camadas
- Trata `RateLimitExceededException` rotando token (preserva comportamento existente de `utils.get_token`)
- Retorna um objeto que expõe a interface usada pelo downstream

Classe `CachedCommit`:
- Wrapper leve sobre um dict produzido por `extract_commit_data()` (em `github_cache.py:140`)
- Expõe atributos usados por `github_data.py::metadata()`:
  - `.sha`
  - `.commit.sha`, `.commit.message`, `.commit.author.name`, `.commit.author.date`
  - `.commit.committer.name`, `.commit.committer.date`
  - `.commit.parents` (lista de objetos com `.sha`)
  - `.commit.verification.verified`
  - `.stats.additions`, `.stats.deletions`, `.stats.total`
  - `.files` (lista de file objects com `.filename`, `.additions`, `.deletions`, `.changes`, `.status`, `.previous_filename`, `.patch`)
  - `.get_comments()` → lista de dicts (não vai à API, retorna do cache)
- Construtor aceita o dict completo e popula sub-objetos mínimos via `SimpleNamespace` ou dataclasses internas

### Alterado: `scripts/github_data.py`

Assinatura de `metadata()`:
```python
def metadata(repo, df, git, config, files_rows=None, *, cache=None, sha_cache=None):
```

Ambos `cache` e `sha_cache` são opcionais (default `None`) para preservar retrocompatibilidade em tests/scripts ad-hoc.

`sort_chain()` passa a aceitar e usar `sha_cache`:
```python
def sort_chain(repo, chain, sha_cache=None):
```

Remover `print(chain_ord_sha)` (linha 92) — ruído no log que contribuía significativamente para o volume (3.5MB/dia).

### Alterado: `scripts/cli.py::get_metadata`

Instanciar `GithubCache(DATA_DIR / "github_cache")` uma vez no início.

Criar `sha_cache = {}` uma vez por run (memoização entre repos; útil se o mesmo SHA aparece em projetos diferentes, raro mas barato).

Passar `cache` e `sha_cache` a cada chamada de `github_data.metadata()`.

No final: log de `cache.stats.summary()` (hits, misses, expired, writes, hit rate).

### Inalterados

- `scripts/lib/github_cache.py` (só passa a ser importado)
- `scripts/pipeline.py`, `scripts/normalize.py`, `scripts/utils.py`
- Todas as outras fases do pipeline

### Config

- `.gitignore`: adicionar `data/github_cache/` (cache local, não versionado)
- Sem env vars novas obrigatórias. `GITHUB_CACHE_TTL_DAYS` continua opcional (default 30).

## Fluxo de dados

### Durante um run

Para cada SHA visto:

1. **`sha_cache[sha]` existe?** → devolve o mesmo objeto PyGithub/CachedCommit memoizado. O(1), 0 reqs.
2. **`cache.get(sha)` devolve dict não-expirado?** → instancia `CachedCommit(dict)`, guarda em `sha_cache`, devolve. ~1ms, 0 reqs.
3. **Miss total** → `repo.get_commit(sha)` via PyGithub. Antes de gravar em cache, chamar `commit.get_comments()` para forçar fetch (a lazy evaluation da PyGithub não persistiria os comments no dict). Gravar em disco e memória. ~300ms, 1-3 reqs (commit + comments + às vezes paginação de files).

### Notas de correção

- **Comments eager fetch**: garantir que `extract_commit_data(commit)` é chamado só depois de `commit.get_comments()` ter sido invocado no objeto, para os comments entrarem no dict cacheado. Caso contrário, o próximo run teria hit de cache sem comments.
- **TTL expirado ou force-push**: `cache.get` devolve `None` → fetch real. Comportamento documentado no docstring de `github_cache.py`.
- **Schema CSV inalterado**: `sources_commits_metadata.csv` mantém as mesmas colunas. Resume natural continua a funcionar (filtro `files != NULL` em `load_missing_commits`).

## Testes

### Reutilizados (sem alteração)

- `tests/test_github_cache.py` — 14 tests (TTL, roundtrip, sharding, corrupção, atomicidade, invalidação, SHAs inválidos, env override)

### Novos

**`tests/test_commit_fetcher.py`** — unit tests do shim:
- `test_memoization_hits_in_memory`: 2ª chamada do mesmo SHA não vai à API nem ao disco
- `test_disk_cache_hit_populates_memory`: hit em disco propaga para `sha_cache`
- `test_miss_calls_api_and_persists`: mock de `repo.get_commit`, verificar `cache.put` chamado
- `test_rate_limit_exception_rotates_token`: comportamento existente preservado
- `test_cached_commit_exposes_pygithub_interface`: `CachedCommit` tem todos os atributos esperados

**`tests/test_enrich_integration.py`** — smoke test end-to-end:
- Fixture com CSV de 3 vulns, chains de 2-3 commits cada, `files=NULL`
- Mock de `Repository` que conta chamadas a `get_commit`
- Assertiva 1: `get_commit` calls = número de SHAs únicos (não multiplicado por N da chain)
- Assertiva 2: segundo run (cache populado) faz 0 calls à API

### Verificação manual pós-deploy

- Correr na VM, comparar entries/h antes/depois (baseline: 25/h)
- Log deve imprimir `cache stats: hits=X misses=Y (Z% hit rate)` no fim da fase metadata

### Scope-out consciente

- PyGithub em si (confiamos na lib; mockamos)
- Rede real (mocks; smoke test offline)
- Correção de conteúdo final do dataset (já coberto por `tests/test_enrich_merge.py`)

## Sequência de deployment

### Fase 1 — desenvolvimento local

1. Implementar `scripts/lib/commit_fetcher.py`
2. Editar `scripts/github_data.py` e `scripts/cli.py`
3. Correr `python -m pytest tests/ -v` — tudo verde
4. Commit local

### Fase 2 — deploy para a VM

5. Sync dos ficheiros para `~/security-patches-dataset/` na VM (via `gcloud compute scp` ou `git pull` conforme workflow preferido)
6. Parar o run actual: `tmux attach -t pipeline`, `Ctrl-C`; ou `kill` dos PIDs (126812 + 129143)
7. Verificar que `data/.../sources_commits_metadata.csv` está intacto com as 939 entries já processadas

### Fase 3 — resume natural

8. Relançar em tmux: `tmux new -s pipeline -d 'cd ~/security-patches-dataset && bash scripts/run_weekly.sh'`
9. Pipeline filtra linhas com `files=NULL`, processa as restantes ~5,275 entries
10. Monitorizar ritmo nas primeiras 10-15 min para validar speedup
11. Ao completar, verificar `cache stats` no log e populaçao de `data/github_cache/`

### Rollback

- `git revert` local + re-sync para a VM
- Cache em disco é append-only e compatível com a versão antiga (não é usada por ela); não há estado corrompido
- Escape hatch: se speedup < 2× após 30 min, parar e debug em vez de deixar a correr mais um dia

## Riscos e mitigação

| Risco | Probabilidade | Mitigação |
|---|---|---|
| `CachedCommit` não expor algum atributo usado downstream | Média | Test `test_cached_commit_exposes_pygithub_interface` valida a interface; grep prévio por `commit.` em `github_data.py` para inventário |
| Comments não persistidos se `extract_commit_data` for chamado antes de `get_comments()` | Baixa | Documentar explicitamente e cobrir com test |
| Cache a crescer sem limite (118k commits × ~10KB cada = ~1.2GB) | Baixa | TTL 30d limita; monitorizar `df` na VM; eviction LRU fica para iteração futura se necessário |
| Retrocompatibilidade com scripts ad-hoc que chamam `metadata()` sem cache | Baixa | `cache` e `sha_cache` são opcionais com default `None`, comportamento cai no fluxo original |
