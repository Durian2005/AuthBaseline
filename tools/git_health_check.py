# -*- coding: utf-8 -*-
"""只读 Git 仓库体检 —— 不执行任何写操作（无 add/commit/checkout/reset/clean）。

覆盖：
  1. 仓库识别（是否存在 .git、仓库根、git 版本）
  2. 分支与上游追踪（含 ahead/behind）
  3. 远程配置与连通性（ls-remote，只读）
  4. 工作区状态（staged / modified / untracked 分类计数）
  5. .gitignore 生效情况（关键大目录是否被忽略）
  6. 本地未推送提交
  7. 完整性校验（fsck）与对象统计
  8. 危险信号汇总（rebase/merge 中断、锁文件、detached HEAD）
"""
import subprocess
import os

GIT = os.environ.get("WB_GIT") or os.path.join(
    os.path.expanduser("~"), ".workbuddy", "binaries", "PortableGit",
    "versions", "1.2.0", "cmd", "git.exe")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def git(*args, timeout=60):
    """执行只读 git 命令，返回 (返回码, 输出文本)"""
    p = subprocess.run(
        [GIT] + list(args),
        cwd=REPO,
        capture_output=True,
        timeout=timeout,
    )
    out = p.stdout.decode("utf-8", errors="replace")
    err = p.stderr.decode("utf-8", errors="replace")
    return p.returncode, (out + err).strip()


def h(title):
    print()
    print("=" * 62)
    print(" " + title)
    print("=" * 62)


# ---------- 1. 仓库识别 ----------
h("[1] 仓库识别")
rc, v = git("--version")
print("git 版本      :", v)
rc, inside = git("rev-parse", "--is-inside-work-tree")
print("是否 git 仓库 :", inside if rc == 0 else "否 (rc=%d)" % rc)
rc, root = git("rev-parse", "--show-toplevel")
print("仓库根目录    :", root)
rc, gd = git("rev-parse", "--git-dir")
print(".git 目录     :", gd)
rc, bare = git("rev-parse", "--is-bare-repository")
print("是否裸仓库    :", bare)

if inside != "true":
    print("\n!! 不是 git 仓库，无需继续检查")
    raise SystemExit(0)

# ---------- 2. 分支状态 ----------
h("[2] 分支与上游追踪")
rc, head = git("rev-parse", "--abbrev-ref", "HEAD")
print("当前 HEAD     :", head)
if head == "HEAD":
    print("  !! detached HEAD —— 不在任何分支上（危险）")
rc, bvv = git("branch", "-vv", "--all")
print("分支列表:")
for line in bvv.splitlines():
    print("   ", line)
rc, ab = git("rev-list", "--left-right", "--count", "HEAD...@{upstream}")
if rc == 0:
    parts = ab.split()
    print("相对上游      : ahead=%s, behind=%s" % (parts[0], parts[1]))
else:
    print("相对上游      : (无上游追踪分支)")
    print("               ", ab.splitlines()[0] if ab else "")

# ---------- 3. 中断状态 / 锁文件 ----------
h("[3] 中断状态与锁文件（危险信号）")
gdir = os.path.join(REPO, ".git")
checks = {
    "rebase 进行中": "rebase-merge",
    "rebase 进行中(apply)": "rebase-apply",
    "merge 进行中": "MERGE_HEAD",
    "cherry-pick 进行中": "CHERRY_PICK_HEAD",
    "revert 进行中": "REVERT_HEAD",
    "bisect 进行中": "BISECT_LOG",
}
found_interrupted = False
for label, path in checks.items():
    if os.path.exists(os.path.join(gdir, path)):
        print("  !! %s  ← .git/%s 存在" % (label, path))
        found_interrupted = True
if not found_interrupted:
    print("  正常：无 rebase/merge/cherry-pick/revert/bisect 中断残留")

lock = os.path.join(gdir, "index.lock")
if os.path.exists(lock):
    print("  !! .git/index.lock 存在 —— 可能有其他 git 进程在跑，或上次异常退出")
else:
    print("  正常：无 index.lock 残留")

# ---------- 4. 远程 ----------
h("[4] 远程配置")
rc, remotes = git("remote", "-v")
print(remotes if remotes else "  (未配置任何远程)")
if remotes:
    for name in sorted({l.split()[0] for l in remotes.splitlines()}):
        rc, url = git("remote", "get-url", name)
        print("\n  远程 '%s' URL: %s" % (name, url))
        rc, out = git("ls-remote", "--heads", name, timeout=45)
        if rc == 0:
            n = len([l for l in out.splitlines() if l.strip()])
            print("    ls-remote 连通 OK，远端分支数 = %d" % n)
        else:
            print("    !! ls-remote 失败（远端不可达或需认证）: %s"
                  % (out.splitlines()[0] if out else "?"))

# ---------- 5. 工作区状态 ----------
h("[5] 工作区状态")
# 注意：不能对 git status --porcelain 的整体输出做 .strip()，
# 否则首行的前导空格会被吃掉，把 " M"(未暂存修改) 误判成 "M "(已暂存)。
p = subprocess.run([GIT, "status", "--porcelain=v1"], cwd=REPO, capture_output=True)
st = p.stdout.decode("utf-8", errors="replace")
lines = [l for l in st.splitlines() if l.strip()]
staged = [l for l in lines if not l.startswith("??") and l[0] != " "]
modified = [l for l in lines if not l.startswith("??") and len(l) > 1 and l[1] == "M"]
untracked = [l for l in lines if l.startswith("??")]
deleted = [l for l in lines if not l.startswith("??") and "D" in l[:2]]
print("  已暂存(staged)   : %d" % len(staged))
print("  已修改(modified) : %d" % len(modified))
print("  已删除(deleted)  : %d" % len(deleted))
print("  未跟踪(untracked): %d" % len(untracked))
print("  合计条目         : %d" % len(lines))
if untracked:
    print("\n  未跟踪文件（前 20）:")
    for l in untracked[:20]:
        print("    ", l[3:])
    if len(untracked) > 20:
        print("     ... 还有 %d 个" % (len(untracked) - 20))
if modified:
    print("\n  已修改文件（前 20）:")
    for l in modified[:20]:
        print("    ", l[3:])

# ---------- 6. .gitignore 生效情况 ----------
h("[6] .gitignore 生效检查（关键大目录是否被忽略）")
gi = os.path.join(REPO, ".gitignore")
print(".gitignore 存在:", os.path.exists(gi))
important = [
    "node_modules",
    "src-tauri/target",
    "AuthClient/node_modules",
    "AuthServer/bin",
    "AuthServer/obj",
    "src-tauri/target/debug",
]
for p in important:
    rc, out = git("check-ignore", "-v", p)
    if rc == 0:
        print("  [忽略] %-28s ← 规则: %s" % (p, out.split(":", 1)[-1].split("\t")[0] if out else "?"))
    else:
        print("  [未忽略] %-28s" % p)

# ---------- 7. 提交历史与未推送 ----------
h("[7] 提交历史")
rc, log = git("log", "--oneline", "--graph", "--decorate", "-12")
print(log if rc == 0 else "  (无提交历史)")
rc, cnt = git("rev-list", "--count", "HEAD")
print("\n本地提交总数  :", cnt if rc == 0 else "0")

rc, unpushed = git("log", "--oneline", "@{upstream}..HEAD")
if rc == 0:
    n = len([l for l in unpushed.splitlines() if l.strip()])
    print("未推送到上游  : %d 个提交" % n)
    for l in unpushed.splitlines()[:10]:
        print("    ", l)

# ---------- 8. 仓库体积与完整性 ----------
h("[8] 仓库体积与对象完整性")
rc, size = git("count-objects", "-vH")
print(size)
print("\nfsck 完整性校验中（只读）...")
rc, fsck = git("fsck", "--no-progress", "--connectivity-only", timeout=180)
if rc == 0 and not fsck:
    print("  OK：对象库完整，无缺失/损坏对象")
else:
    print("  rc=%d" % rc)
    for l in fsck.splitlines()[:30]:
        print("   ", l)

h("[9] 结论汇总")
print("  仓库根      :", root)
print("  当前分支    :", head)
print("  远程        :", remotes.splitlines()[0] if remotes else "无")
print("  未提交条目  :", len(lines))
print("  中断残留    :", "有(见第3节)" if found_interrupted else "无")
