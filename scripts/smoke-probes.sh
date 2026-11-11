# shellcheck shell=bash
# scripts/smoke.sh 的一项一项探测，跟着插件走。没写的项会 FAIL 并给出写法，不会默认放行。
#
# 变量别叫 state：shellcheck 把这份文件连着 probes.sh 一起分析，probes.sh 自己也读一个 dev.sh 提供的 state；
# 子壳体函数（fn() ( … )）里给 state 赋值，SC2031 就报在 probes.sh 上，CI 红。
#
# 变量：两套冒烟环境（dev.sh smoke、正式 e2e 套件）都给的只有 SMOKE_STATE、SMOKE_JAR、SMOKE_WEB_URL、
#       SMOKE_OWNER、SMOKE_BASE、SMOKE_TOKEN、SMOKE_INSTANCE 和 web_get、dweb。SMOKE_WEB_URL 的含义两边不同
#       （dev.sh smoke 是带路径的网页入口，正式套件剥成只有 origin），拼 API 和挑本插件都用 _gf_origin 取的
#       origin；网页入口从核心的插件列表查（web_url 带清单的入口路径），不依赖 SMOKE_WEB_ORIGIN/SMOKE_PLUGIN_ID
#       （正式套件的钩子约定里没有这两个）。
#
# 页面：web_assert 从标准输入读页面，命中的确是应用的真实页面时返回 0。
# 身份：identity_check 只证明身份：用应用自己的"当前用户"接口断言认出的是用户管理员，不碰应用里的数据。
#       数据断言（是否配置过、有几条、内容对不对）全部交给 data_write / data_check：冒烟第 1 项会先装升级
#       起点写数据，身份探针再断言"数据目录是空的"就会红。接口回字段时也只看类型（如 configured 是布尔、
#       nodes 是数字），值和条数留给 data_check。
#       没有用户体系时写 IDENTITY_NA=1，并在 SMOKE_NOTE 里写原因。dweb / web_get 是带用户会话的请求助手，可继续走应用自己的登录链。
#       SSO 登录跳转不用自己写表单逻辑：dweb --sso 会从清单 webui.path 的入口出发（没写就是 /），提交核心
#       登录页的 JS 自动表单并跟完重定向，返回的页面已带应用的登录态。
# 工具：MCP_TOOL 写一个只读工具名（可带插件前缀），MCP_ARGS 是 JSON 参数；mcp_assert 从标准输入读调用结果。
#       要断言多个工具时改成写 mcp_check；调用前要备数据时写 before_mcp。
# 数据：合并前要验证"升级/重装不丢用户数据"时写 data_write 和 data_check（两个都写才跑）：data_write 用随机标记写
#       一条数据并把标记原样存进 $SMOKE_STATE，data_check 读回标记去应用里找，对不上就打印看到了什么并返回非 0。
#       应用不存用户数据时写 DATA_NA=1（两项记 N/A）。
# 装之前要准备（如先配出口代理）：写 before_install。

# sso=oidc：打开网页（清单入口 /api/auth/oidc）直跳云吞登录，应用不发自己的会话 Cookie，
# 登录态是回调最后一跳地址里的 JWT（/<语言>/auth/<jwt>），探针从这里取，之后带 Bearer 调应用自己的接口。
# 清单没有 mcp：上游自带 MCP，但它的访问令牌只能由主人登录后在应用里创建，装好时给不出值
# （mcp.headers 要求装好即有值，见 PR 的"底座的问题"）。
# shellcheck disable=SC2034  # SSO/MCP 由冒烟套件读取
SSO=oidc
MCP=0

web_assert() { grep -qi '<title[^>]*>Ghostfolio'; }   # SPA 的 index.html 对任何路径都返回，标题即特征

# ---------- 探针内部助手：只用两套冒烟环境都给的变量 ----------
GF_JWT=""

_gf_origin() { # SMOKE_WEB_URL 两边含义不同（一个带入口路径、一个只有 origin），拼 API 前取 origin
  local u="${SMOKE_WEB_URL%%\?*}" rest="${SMOKE_WEB_URL#*://}"
  printf '%s://%s' "${u%%://*}" "${rest%%/*}"
}

gf_token() { # 登进核心 → 应用 /api/auth/oidc → 核心登录页自动放行 → 回调 → 302 到 /<语言>/auth/<jwt>。
             # 同一进程缓存；输出 JWT，诊断走标准错误。
  local entry final jwt plugins
  if [[ -z "$GF_JWT" ]]; then
    [[ -n "${SMOKE_JAR:-}" && -n "${SMOKE_BASE:-}" && -n "${SMOKE_TOKEN:-}" && -n "${SMOKE_WEB_URL:-}" ]] ||
      { echo "缺冒烟变量：SMOKE_JAR/SMOKE_BASE/SMOKE_TOKEN/SMOKE_WEB_URL" >&2; return 1; }
    # 核心会话补进 jar：-b 保留已有 cookie（只写 -c 会把 jar 里别的域的会话抹掉）。
    curl -sS --noproxy '*' --max-time 120 -o /dev/null -b "$SMOKE_JAR" -c "$SMOKE_JAR" \
      --data-urlencode "token=${SMOKE_TOKEN}" "$SMOKE_BASE/_wonton/login" ||
      { echo "主人令牌登录不了核心" >&2; return 1; }
    # 网页入口从核心查：web_url 带清单的入口路径（如 /api/auth/oidc），链必须从入口出发——SMOKE_WEB_URL 在
    # 正式套件里只有 origin，从它出发只会落到应用根（/ → /<语言>），OIDC 根本不走。按 origin 前缀挑本插件。
    plugins="$(curl -sS --noproxy '*' --max-time 120 -H "Authorization: Bearer ${SMOKE_TOKEN}" \
      "$SMOKE_BASE/_wonton/api/plugins")" || { echo "列不出插件" >&2; return 1; }
    entry="$(jq -r --arg o "$(_gf_origin)" \
      '[.plugins[] | .web_url // empty] | map(select(startswith($o))) | first // empty' <<<"$plugins")" ||
      { echo "读不出网页入口" >&2; return 1; }
    [[ -n "$entry" ]] || { echo "核心没给本插件的网页入口" >&2; return 1; }
    # Ghostfolio 的登录态不是 cookie，是回调最后一跳地址里的 JWT（/<语言>/auth/<jwt>），走一遍链取它。
    final="$(curl -sS --noproxy '*' --max-time 120 -o /dev/null -L -b "$SMOKE_JAR" -c "$SMOKE_JAR" \
      -H 'Accept: text/html' -w '%{url_effective}' "$entry")" ||
      { echo "OIDC 登录链请求失败" >&2; return 1; }
    jwt="${final##*/auth/}"
    [[ -n "$jwt" && "$jwt" != "$final" ]] ||
      { echo "登录没拿到 JWT（入口 $entry，最后一跳是 $final；跳到 /auth 说明 OIDC 失败，看应用日志）" >&2; return 1; }
    GF_JWT="$jwt"
  fi
  printf '%s' "$GF_JWT"
}

gf_api() { # <方法> <路径> [JSON 正文]：带应用 JWT 经网关调应用接口，输出响应。
  local method="$1" path="$2" body="${3:-}" jwt args=()
  jwt="$(gf_token)" || return 1
  args=(-sS --noproxy '*' --max-time 120 -b "$SMOKE_JAR" -H "Authorization: Bearer $jwt" -X "$method")
  if [[ -n "$body" ]]; then
    args+=(-H 'Content-Type: application/json' -d "$body")
  fi
  curl "${args[@]}" "$(_gf_origin)$path"
}

identity_check() { # 应用认出的是主人本人：这个 JWT 调得动"当前用户"接口，且应用里只有这一个用户——
                   # 是刚才这次 OIDC 登录建出来的（provider=OIDC 的管理员）。
  local me users
  me="$(gf_api GET /api/v1/user)" || { echo "调 /api/v1/user 失败"; return 1; }
  jq -e '.id | type == "string" and length > 0' <<<"$me" >/dev/null ||
    { echo "当前用户接口没认出登录态：$(head -c 200 <<<"$me")"; return 1; }
  users="$(gf_api GET /api/v1/users)" || { echo "调 /api/v1/users 失败：$users"; return 1; }
  jq -e '.count == 1 and .users[0].provider == "OIDC" and .users[0].role == "ADMIN"' <<<"$users" >/dev/null ||
    { echo "应用里的用户不是 OIDC 建的管理员（或不止一个）：$(head -c 300 <<<"$users")"; return 1; }
}

# 保数据：建一个名字带随机标记的账户，标记写进 $SMOKE_STATE；升级/重装后按 id 读回来核对名字。
data_write() {
  local marker out id
  marker="probe-$(date +%s)-$RANDOM"
  out="$(gf_api POST /api/v1/accounts \
    "{\"name\":\"$marker\",\"currency\":\"USD\",\"platformId\":null}")" ||
    { echo "建账户失败：$out"; return 1; }
  jq -e --arg m "$marker" '.name == $m and (.id | length > 0)' <<<"$out" >/dev/null ||
    { echo "创建响应里没有账户：$(head -c 200 <<<"$out")"; return 1; }
  id="$(jq -r '.id' <<<"$out")"
  printf 'GF_ACCOUNT_ID=%q\nGF_MARKER=%q\n' "$id" "$marker" > "$SMOKE_STATE"
}

data_check() {
  local out
  # shellcheck source=/dev/null  # SMOKE_STATE 是套件准备的数据标记文件，路径在运行时才有
  source "$SMOKE_STATE"
  out="$(gf_api GET /api/v1/accounts)" || { echo "列账户失败：$out"; return 1; }
  jq -e --arg id "$GF_ACCOUNT_ID" --arg m "$GF_MARKER" \
    '.accounts[] | select(.id == $id) | .name == $m' <<<"$out" >/dev/null ||
    { echo "找不到写进去的账户（id=$GF_ACCOUNT_ID 标记=$GF_MARKER）：$(head -c 300 <<<"$out")"; return 1; }
}
