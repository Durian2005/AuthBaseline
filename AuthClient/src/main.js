import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import { initApiRoot } from './api/client'
import './styles/tokens.css'
import './styles/base.css'

// 桌面端（Tauri）：向 Rust 侧索取 sidecar 后端的真实地址。
// 这里刻意不 await —— client.js 内部所有请求都会等待该 Promise，
// 因此"会话恢复"这类早期请求不会抢在地址下发之前发出；浏览器环境下它是空操作。
initApiRoot()

createApp(App).use(createPinia()).mount('#app')
