# Patch de referência

Todo o trabalho parte de uma versão fixa do patch. Se uma versão posterior da
série mudar algo relevante, a mudança entra como experimento separado.

| Campo | Valor |
| --- | --- |
| Série | Quinta versão (v5), com 14 patches |
| Patch estudado | `[PATCH v5 12/14] module: Introduce hash-based integrity checking` |
| Autor | Thomas Weißschuh |
| Data | 5 de maio de 2026 |
| Arquivo da lista | <https://lkml.iu.edu/2605.0/04798.html> |
| Identificador da mensagem | `20260505-module-hashes-v5-12-e174a5a49fce@weissschuh.net` |

## Arquivos que o modelo reproduz

| Arquivo do patch | Blob no diff | O que tem | Onde está no modelo |
| --- | --- | --- | --- |
| `kernel/module/hashes.c` | `3d3cf0366f75` | `hash_entry`, `hash_data`, `module_hashes_verify_proof`, `module_hash_check` | `ref/merkle.py`, funções de mesmo nome |
| `scripts/modules-merkle-tree.c` | `10e3455d5d7a` | `log2_roundup`, `build_merkle`, `build_proof`, `write_merkle_root` | `ref/merkle.py`, `log2_roundup` e classe `MerkleTree` |
| `include/linux/module_hashes.h` | `53b34fa12f2d` | `struct module_hashes_proof`, `struct module_hashes_root` | `ref/merkle.py`, `make_proof` e classe `Root` |

## O que o patch define

- Folha: `SHA-256(0x01 || pos || módulo)`, com `pos` em 32 bits big-endian.
- Nó interno: `SHA-256(0x02 || esquerdo || direito)`.
- Posição de um módulo: o índice dele em `modules.order`.
- Níveis: `log2_roundup(n)`, com no mínimo um nível.
- Quantidade ímpar de nós em um nível: o último é pareado consigo mesmo.
- Prova: `pos` em 4 bytes seguido de um hash irmão por nível, ou seja, `4 + 32 x níveis` bytes.
- Raiz: número de níveis e hash. O número de módulos não é guardado.
- Sem módulos: raiz com zero níveis e hash só de zeros.
- Verificação: tamanho errado devolve `-ENOPKG`; caminho que não chega à raiz devolve `-ENOKEY`.

## Como a conferência foi feita

Primeiro por leitura, função a função, do patch contra `ref/merkle.py`.

Em 25/11/2026 rodamos o próprio código do patch num container Linux. A
ferramenta de compilação gerou raízes e provas idênticas às do modelo em 76
árvores (0 a 8.192 módulos), e o verificador do kernel decidiu os 100 vetores
como o modelo. Os arquivos usados estão em `patch-v5/` e o resultado em
`docs/comparacao-com-patch.md`. Para refazer:
`python3 -m tools.comparar_com_patch --gravar` (precisa de Docker).
