// ESLint 扁平配置（ESLint 9+ / 10）
//
// 设计目标：**只开"真 bug 类"规则**，不引入风格规则。
//
// 为什么不用 js.configs.recommended / vue 的 flat/recommended：
//   本项目前端是 8000+ 行的既有代码，风格类规则（缩进、引号、命名、组件名多词…）
//   会一次产生几百条告警。那样得到的"告警基线"是个大数字，谁也不会去看，
//   最终只会演变成"跑 lint 时加个 --quiet 或者干脆不跑"。
//   所以这里的规则集只有一个判据：**命中了就是潜在 bug，不是审美问题**。
//
// 配套约定（重要，别改成 "--fix 全量清理"）：
//   - 存量告警**不要求**清零，只要求"你改动的文件不新增告警"。
//   - 判据：改动前后各跑一次 `npm run lint`，比较总数与文件清单。
//   - 需要放宽时优先在文件内用 `// eslint-disable-next-line <规则> 原因`，
//     不要动全局规则 —— 全局关掉会让后来的人失去这层保护。

import pluginVue from 'eslint-plugin-vue'
import globals from 'globals'

export default [
  {
    // 构建产物、依赖、遗留原版实现（保留作对照，不参与检查）
    ignores: ['dist/**', 'node_modules/**', 'legacy-wwwroot/**', 'public/**'],
  },

  // Vue 的 essential 档：解析 SFC + 会在编译期/运行期真出错的规则
  // （模板语法错误、重复 key、改 props、v-for 缺 key、computed 里有副作用…）
  ...pluginVue.configs['flat/essential'],

  {
    files: ['**/*.{js,mjs,cjs,vue}'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: { ...globals.browser },
    },
    rules: {
      // —— 语言层：几乎必然是真 bug ——
      'no-dupe-keys': 'error',
      'no-dupe-args': 'error',
      'no-dupe-class-members': 'error',
      'no-duplicate-case': 'error',
      'no-unreachable': 'error',
      'no-func-assign': 'error',
      'no-import-assign': 'error',
      'no-self-assign': 'error',
      'no-self-compare': 'error',
      'no-obj-calls': 'error',
      'no-sparse-arrays': 'error',
      'no-unsafe-negation': 'error',
      'no-unsafe-optional-chaining': 'error',
      'use-isnan': 'error',
      'valid-typeof': 'error',
      'no-redeclare': 'error',

      // `x = 1` 出现在条件里 ⇒ 想写的是 `==`
      'no-cond-assign': 'error',
      // 恒真/恒假的字面量条件 ⇒ 死代码或逻辑写反
      'no-constant-condition': ['error', { checkLoops: false }],

      // 拼错的变量名 —— 本规则是"没有类型检查时最值钱的一条"
      'no-undef': 'error',

      // 未使用变量：只提示不阻断。渐进重构中大量出现"暂时留着"的引用，
      // 定成 error 会让 lint 从"安全网"变成"绊脚石"。
      'no-unused-vars': [
        'warn',
        {
          args: 'none', // 回调签名常按接口固定，未用的位置参数很常见
          caughtErrors: 'none',
          varsIgnorePattern: '^_',
          ignoreRestSiblings: true,
        },
      ],

      // 纯约定类，与 bug 无关，关掉
      'vue/multi-word-component-names': 'off',
    },
  },

  // 构建脚本（Node 环境，不是浏览器）
  {
    files: ['vite.config.js', 'vite.config.mjs', '*.config.js'],
    languageOptions: { globals: { ...globals.node } },
  },
]
