---
name: update-ip2region
description: 用于手动更新IP地址定位库`ip2region_v4.xdb`和`ip2region_v6.xdb`
---

# 名称
手动更新IP地址定位库文件

# 描述
- 用户手动更新IP地址定位库，包括`ip2region_v4.xdb`和`ip2region_v6.xdb`两个文件
- 文件位置：[ip2region_v4.xdb](../../../internal/module/proxy/db/ip2region_v4.xdb)、[ip2region_v6.xdb](../../../internal/module/proxy/db/ip2region_v6.xdb)
- 最新文件在github项目，项目地址：`https://github.com/lionsoul2014/ip2region.git`
- 最新文件在项目的data目录，相对路径：`data/ip2region_v4.xdb`、`data/ip2region_v6.xdb`
- 更新步骤：将文件从github下载后覆盖本项目同名文件

# 注意
只有用户主动要求更新时才执行，不要自动执行此任务
