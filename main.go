// certsync:集中签发 + OSS 加密中转 + 多机拉取部署的泛域名证书管理(设计:docs/DESIGN.md)。
package main

import "github.com/hy/certsync/internal/cli"

// Version 编译时注入:make build 会以 -ldflags "-X main.Version=$(git describe)" 覆盖。
var Version = "dev"

func main() {
	cli.Version = Version
	cli.Execute()
}
