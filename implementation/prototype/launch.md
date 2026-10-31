# 当前可重复部署入口

完整的 Krill–Routinator–FRR 基线和 DA-aware FRR 执行已经迁移到：

```bash
cd phase6_system/e2e
make test
make experiment
```

架构、清理范围、实验矩阵和结果目录见 `e2e/README.md`。以下内容仅保留为
2026-07-06 历史手工部署记录，不再作为论文实验的复现入口。

# 历史：pull 镜像（私有仓库方式）或从源码编译
# 方式一：私有仓库
docker pull 905779660/testbed
docker pull 905779660/routinator

# 方式二：从源码编译（当 Docker Hub 不可达时，通过 Daocloud 镜像站拉基镜像）
# 1) 解压 stripe-roa-system.zip
# 2) docker tag docker.m.daocloud.io/library/rust:bookworm rust:bookworm
# 3) docker tag docker.m.daocloud.io/library/rust:1.88-bullseye rust:1.88-bullseye
# 4) cd dockerfiles/testbed && docker build -t stripe-testbed .
# 5) cd dockerfiles/stripe-roa-routinator
#    sed -i 's/default = \[ "socks", "ui"\]/default = [ "socks"]/' routinator/Cargo.toml
#    docker build -t stripe-routinator .

# 启动容器
docker run -itd --name testbed --hostname testbed -p 3000:3000 stripe-testbed /bin/bash
docker run -itd --name routinator -p 3323:3323 -p 3333:3333 stripe-routinator /bin/bash

# testbed容器中命令，启动krill服务
1. sh <home>/bin/entrypoint.sh
2. ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1 -d '/'

# testbed: 生成 SAN 服务器证书（修复 CaUsedAsEndEntity / NotValidForName）
3. cd /etc/pki/CA
4. 创建 san.cnf（DNS:testbed + IP:172.17.0.2），生成 server.crt + server_san.key
5. 配置 nginx HTTPS:443 反代 → Krill HTTPS:3000
6. nginx -s reload

# testbed: 签发 ROA，复现 RFC 6811 语义冲突
7. export KRILL_CLI_TOKEN="<set-testbed-token>"
8. krillc roas update -c testbed --add "10.0.0.0/16 => 64501"
9. krillc roas list -c testbed

# routinator容器中命令，配置域名，下载TAL，启动routinator
1. echo '172.17.0.2 testbed' >> /etc/hosts （172.17.0.2替换为testbed容器中第二步输出的ip）
2. rm <home>/tals/*
3. wget -P <home>/tals/ https://testbed/ta/ta.tal --no-check-certificate
4. routinator --extra-tals-dir="<home>/tals/" --logfile="<home>/routinator.log"  server --rtr 0.0.0.0:3323 --http 0.0.0.0:3333 &

# 验证
5. routinator vrps                                  # 检查 VRP: AS64501,10.0.0.0/16,16,16,ta
6. routinator validate --prefix 10.0.0.0/16 --asn 64501    # → valid
7. routinator validate --prefix 10.0.0.0/16 --asn 64502    # → invalid (hijack)
8. routinator validate --prefix 10.0.1.0/24 --asn 64502    # → invalid (semantic conflict!)

# 注：可通过sudo docker exec -it CONTAINER_NAME /bin/bash 进入某容器命令行，testbed的CONTAINER_NAME为testbed，routinator的为routinator
