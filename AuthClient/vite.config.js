import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 后端（ASP.NET Core）默认监听 http://localhost:5007，前端不做任何后端改动。
const BACKEND = 'http://localhost:5007'

// 两套产物，互不干扰：
//   默认模式      → AuthServer/wwwroot，由 ASP.NET Core 的 UseStaticFiles 托管（浏览器打开，同源 /api）
//   desktop 模式  → AuthClient/dist，由 Tauri 打包进桌面应用；
//                   此时页面源是 tauri:// 而非后端，/api 相对路径不可用，
//                   运行期通过 Tauri IPC 拿到 sidecar 后端的真实地址（见 src/api/client.js）。
export default defineConfig(({ mode }) => {
  const isDesktop = mode === 'desktop'

  return {
    plugins: [vue()],
    server: {
      port: 5173,
      strictPort: false,
      proxy: {
        '/api': {
          target: BACKEND,
          changeOrigin: true
        }
      }
    },
    build: {
      outDir: isDesktop ? 'dist' : '../AuthServer/wwwroot',
      emptyOutDir: true,
      assetsDir: 'assets',
      chunkSizeWarningLimit: 900
    }
  }
})
