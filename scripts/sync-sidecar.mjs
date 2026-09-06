/**
 * 把 dotnet publish 出来的后端可执行文件，按 Tauri sidecar 的命名规范
 * 复制到 src-tauri/binaries/ 下。
 *
 * Tauri 约定：外部二进制必须命名为 `<名称>-<目标三元组>[.exe]`，
 * 例如 authserver-x86_64-pc-windows-msvc.exe；
 * 配置里只需写 "binaries/authserver"，Tauri 会自动补全后缀。
 *
 * 用法：npm run sync:sidecar
 */
import { copyFileSync, existsSync, mkdirSync, statSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')

// 目标三元组与本机架构绑定；换平台交叉编译时需同步调整
const TARGET_TRIPLE = 'x86_64-pc-windows-msvc'
const SIDECAR_NAME = 'authserver'

const src = join(root, 'AuthServer', 'publish', 'AuthServer.exe')
const dst = join(root, 'src-tauri', 'binaries', `${SIDECAR_NAME}-${TARGET_TRIPLE}.exe`)

if (!existsSync(src)) {
  console.error(`未找到后端发布产物：${src}`)
  console.error('请先执行：npm run publish:backend')
  process.exit(1)
}

mkdirSync(dirname(dst), { recursive: true })
copyFileSync(src, dst)

const sizeMB = (statSync(dst).size / 1024 / 1024).toFixed(1)
console.log(`sidecar 已更新：${dst}（${sizeMB} MB）`)
