# Código do patch

Os arquivos desta pasta são os do patch v5 12/14 do Weißschuh, sem nenhuma alteração, nos mesmos caminhos da árvore do kernel. Servem para compilar e rodar o código do patch e comparar com o modelo (`python3 -m tools.comparar_com_patch`).

| Arquivo | De onde veio | Hash de blob |
| --- | --- | --- |
| `scripts/modules-merkle-tree.c` | arquivo novo do patch | `10e3455d5d7a` |
| `kernel/module/hashes.c` | arquivo novo do patch | `3d3cf0366f75` |
| `include/linux/module_hashes.h` | arquivo novo do patch | `53b34fa12f2d` |
| `scripts/include/xalloc.h` | Linux, com o patch aplicado | `8294bc0b836f` |
| `tools/include/uapi/linux/module_signature.h` | Linux, com o patch aplicado | `78e206996eed` |
| `scripts/ssl-common.h` | Linux, o patch não mexe | `2db0e181143c` |

## Como foram obtidos

Os três arquivos novos saíram do diff publicado em <https://lkml.iu.edu/2605.0/04798.html>. O arquivo da lista esconde o domínio dos e-mails nas linhas de copyright. Recolocamos `weissschuh.net` e `breakpoint.cc` e só aceitamos porque o hash de blob passou a bater com a linha `index` do diff.

Os outros três vieram do Linux no GitHub, commit `4dce97c6c265`. Os de base batiam com o lado "antes" do diff, e depois de aplicar o patch passaram a bater com o lado "depois".

O hash de blob é o que o `git hash-object` calcula. Um teste (`tests/test_comparacao_com_patch.py`) confere todos a cada rodada, e o script da comparação não roda se algum não bater.

## Licença

Os arquivos continuam com a licença indicada no cabeçalho de cada um (GPL-2.0 ou LGPL-2.1). Nada desta pasta é código nosso. O que fizemos para compilar fora do kernel está em `tools/patch_no_linux/`.
