# krillc roas update 命令详解

## 概述

`krillc roas update` 用于向指定 CA 添加或删除 ROA（Route Origin Authorization）授权配置。Krill 收到更新后会根据新的授权配置自动签发或撤销 RFC 6482 ROA 对象。

## 基本语法

```
krillc roas update -c <CA名称> [--add <ROA定义>]... [--remove <ROA定义>]... [--dryrun|--try]

krillc roas update -c <CA名称> --delta <文件路径> [--dryrun|--try]
```

更新内容的提供方式有两种，必须二选一：

- **命令行方式**：通过 `--add` 和 `--remove` 参数直接在命令行指定
- **文件方式**：通过 `--delta` 参数从文件批量读取

两种方式不能混用。

---

## 公共参数

| 参数 | 必填 | 说明 |
|---|---|---|
| `-c`, `--ca <name>` | 是 | 要操作的 CA 名称。也可通过环境变量 `KRILL_CLI_MY_CA` 设置 |

---

## 方式一：`--add` / `--remove`（命令行直接指定）

```
krillc roas update -c my_ca \
  --add "192.168.0.0/16 => 64496" \
  --add "10.0.0.0/8-16 => 64496 # 注释" \
  --remove "172.16.0.0/12 => 64500"
```

- `--add` 和 `--remove` 均可多次使用，可在同一条命令中混合出现
- `--add` 的 ROA 定义可以附带注释（`#` 之后的部分）
- `--remove` 的 ROA 定义中注释会被忽略

---

## 方式二：`--delta <file>`（从文件批量读取）

```
krillc roas update -c my_ca --delta /path/to/delta.txt
```

### Delta 文件格式

```
# 井号开头的行为注释，会被忽略
A: 192.168.0.0/16 => 64496 # 行内注释
A: 192.168.1.0/24 => 64496
R: 10.0.0.0/8 => 65500
```

规则：
- `A:` 前缀表示添加（Add），后面跟完整的 RoaConfiguration 格式（支持行内注释）
- `R:` 前缀表示删除（Remove），后面跟 RoaPayload 格式（行内注释会被忽略）
- 以 `#` 开头的行为注释行，会被忽略
- 空行会被忽略

---

## ROA 定义格式详解

### 基础格式

```
<prefix>[长度选项] => <ASN> [inclusive|exclusive] [# comment]
```

解析逻辑位于 [src/commons/api/roas.rs](dockerfiles/testbed/krill/src/commons/api/roas.rs) 的 `RoaPayload::from_str()` 和 `RoaConfiguration::from_str()` 中。

### 1. 最简形式（精确前缀）

```
192.168.0.0/16 => 64496
```

含义：授权 AS64496 宣告 `192.168.0.0/16` 这个精确前缀。此时 max_length 等于前缀自身长度（16），即只允许宣告恰好 /16 的这个前缀。

### 2. 带 max_length（允许宣告更具体的子前缀）

```
192.168.0.0/16-24 => 64496
```

含义：授权 AS64496 宣告 `192.168.0.0/16` 下 /17 到 /24 之间的任意子前缀。

- `-` 后面的数字是 max_length
- max_length 必须 >= 前缀自身长度
- IPv4 的 max_length 上限为 32
- IPv6 的 max_length 上限为 128

### 3. 带 min_length + max_length + inclusivity（更精细的范围控制）

```
10.10.0.0/25, 26-27 => 65504 exclusive
```

含义：授权 AS65504 宣告 `10.10.0.0/25` 下 /26 到 /27 之间的子前缀，且为排他性（exclusive）。

- `, 26-27` 中 `26` 是 min_length，`27` 是 max_length
- min_length 必须 >= 前缀自身长度
- min_length 必须 <= max_length
- **使用 min_length 时，必须同时指定 `inclusive` 或 `exclusive`**，否则解析失败
- 本定制原型将 `inclusive` 编码到 RTR prefix PDU 的保留 flag bit 1
  (`0x02`)，将 `exclusive` 编码到 bit 2 (`0x04`)；bit 0 仍是标准
  announce/withdraw 标志。
- 这不是 RFC 8210 兼容扩展。实测 stock FRR 10.6.1 在收到该 PDU 后断开
  RTR 连接，因此 DA provenance 通过 `e2e/` 中的本地 API 传给 FRR，绝不
  映射成普通 Valid VRP。

### 4. IPv6 前缀

```
2001:db8::/32-48 => 64496
2001:db8::/32, 33-40 => 64496 exclusive
```

与 IPv4 格式完全一致。系统通过前缀中是否包含 `.` 来自动区分 IPv4 和 IPv6。

### 5. 注释（仅 `--add` 有效）

`--add` 的 ROA 定义支持在末尾添加注释：

```
192.168.0.0/16 => 64496 # 为客户A配置的ROA
```

`#` 之后的部分会被存储为注释信息。`--remove` 中如果写了注释则会被忽略。

### 格式校验规则总结

| 校验项 | 规则 |
|---|---|
| prefix 为 IPv4 | max_length ∈ [prefix_len, 32] |
| prefix 为 IPv6 | max_length ∈ [prefix_len, 128] |
| 未指定 max_length | 等同于 max_length = prefix_len |
| 指定了 min_length | 则必须同时指定 max_length 和 inclusivity |
| min_length | 必须 >= prefix_len 且 <= max_length |
| ASN | 纯数字，无 "AS" 前缀（如 `64496`，不能写 `AS64496`） |

---

## 可选模式标记

| 标记 | 说明 |
|---|---|
| `--dryrun` | 模拟执行更新，返回此次变更范围内的完整 BGP 对比分析报告，不实际修改 ROA 配置 |
| `--try` | 尝试执行更新，如果可能导致路由不可达等问题则返回分析和建议，不实际修改 ROA 配置 |

- `--dryrun` 和 `--try` 互斥，不能同时使用
- 两个都不加则真正执行 ROA 更新

---

## 完整示例

### 查看当前 ROA

```bash
krillc roas list -c my_ca
```

### 添加单条 ROA

```bash
krillc roas update -c my_ca --add "192.168.0.0/16 => 64496"
```

### 添加带 max_length 的 ROA

```bash
krillc roas update -c my_ca --add "10.0.0.0/8-16 => 64496"
```

### 同时添加和删除

```bash
krillc roas update -c my_ca \
  --add "192.168.1.0/24 => 64500 # 新客户" \
  --remove "192.168.2.0/24 => 64500"
```

### 模拟执行（dryrun）

```bash
krillc roas update -c my_ca \
  --add "192.168.0.0/16 => 64496" \
  --dryrun
```

### 从文件批量操作

```bash
cat > /tmp/roa_delta.txt << 'EOF'
# 批量迁移 ROA 配置
A: 192.168.0.0/16 => 64496 # 主网段
A: 192.168.1.0/24 => 64496
A: 2001:db8::/32-48 => 64496
R: 10.0.0.0/8 => 64496
EOF

krillc roas update -c my_ca --delta /tmp/roa_delta.txt
```

### 添加带 inclusivity 的 ROA

```bash
krillc roas update -c my_ca \
  --add "10.10.0.0/25, 26-27 => 65504 exclusive"
```

---

## 相关命令

| 命令 | 说明 |
|---|---|
| `krillc roas list -c <ca>` | 列出当前 CA 的所有 ROA 授权 |
| `krillc roas bgp analyze -c <ca>` | 完整报告：当前 ROA vs 已知 BGP 宣告 |
| `krillc roas bgp suggest -c <ca>` | 根据 BGP 宣告给出 ROA 配置建议 |
