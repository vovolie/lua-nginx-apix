local ngx = ngx
local ngx_log = ngx.log
local ngx_err = ngx.ERR
local ngx_debug = ngx.DEBUG
local xxtea = require('xxtea')
local json = require("cjson.safe")
local url = require("url")
local resty_env = require('env')
local random = require('random')
-- local multipart_parser = require('resty.multipart.parser')

local ok, new_tab = pcall(require, "table.new")
if not ok or type(new_tab) ~= "function" then
    new_tab = function(_, _) return {} end
end

local _M = new_tab(0, 5) -- Change the second number.

local ENV_DEBUG = resty_env.get('LUA_DEBUG')
local DEBUG = false
if ENV_DEBUG == 'true' then
    DEBUG = true
end

_M.VERSION = "0.01"

local HTTP_METHOD = {
    ['GET'] = ngx.HTTP_GET,
    ['POST'] = ngx.HTTP_POST,
    ['HEAD'] = ngx.HTTP_HEAD,
    ['PUT'] = ngx.HTTP_PUT,
    ['DELETE'] = ngx.HTTP_DELETE,
    ['OPTIONS'] = ngx.HTTP_OPTIONS
}

function _M.init()
    ORGIN_KEY = resty_env.get('PARAM_ENCRYPT_KEY')
    ngx_log(ngx_err, 'PARAM_ENCRYPT_KEY: ' .. ORGIN_KEY)
    KEY = ngx.md5(ngx.md5(ORGIN_KEY))
    -- 取两次MD5当成密钥
    if DEBUG then
        ngx_log(ngx_err, 'key: ' .. KEY)
    end
end

function _M.decrypt()
    local request_host = ngx.var.host
    -- local request_uri = ngx.unescape_uri(ngx.var.uri)
    -- local request_scheme = ngx.var.scheme
    -- local request_method = ngx.var.request_method
    -- local request_headers = ngx.req.get_headers()
    local request_remote_addr = ngx.var.remote_addr
    local xforwarded = ngx.var.http_x_forwarded_for
    ngx.req.read_body() -- explicitly read the req body  if body > client_body_buffer_size! you need use ngx.req.get_body_file or client_body_in_file_only option opening.
    local data = ngx.req.get_body_data()
    ngx.ctx.path = '/'  -- 默认path for prometheus
    ngx.ctx.method = 'GET'


    if xforwarded == nil then
        -- 考虑没有前置负载均衡时，默认remote_addr
        xforwarded = request_remote_addr
    end

    if data then
        local len = string.len(data)
        -- 取两位密钥长度
        local key_len = tonumber(string.sub(data, -2))
        local decrypt_key = string.sub(data, len - 2 - key_len, len - 2)
        local real_data = string.sub(data, 1, len - 2 - key_len)
        local content = ngx.decode_base64(real_data)
        if content == nil then
            ngx_log(ngx_err, 'content is nil!')
            ngx.say('404 NOT FOUND')
            ngx.status = 404
            return
        end
        if ORGIN_KEY == nil then
            ngx.say('502 Bad Gateway')
            ngx.status = 502
            return
        end
        local decrypt_data = xxtea.decrypt(content, decrypt_key)
        if decrypt_data then
            local entry = json.decode(decrypt_data)
            if not entry then
                ngx_log(ngx_err, 'json decode request body err!')
                ngx.say('502 Bad Gateway')
                ngx.status = 502
                return
            else
                local debug_headers = ''
                if entry['headers'] ~= nil then
                    local internal_headers = entry['headers']
                    internal_headers['remote_addr'] = xforwarded
                    internal_headers['x-forwarded-for'] = xforwarded
                    if DEBUG then
                        ngx_log(ngx_err, "http_x_forwarded_for: " .. xforwarded)
                    end
                    internal_headers['Accept-Encoding'] = ''
                    -- 禁止与backend 协商为gzip
                    if entry['ct'] ~= nil then
                        internal_headers['Content-Type'] = entry['ct']
                    end
                    for k, v in pairs(internal_headers) do
                        ngx.req.set_header(k, v)
                        debug_headers = debug_headers .. ' key: ' .. k .. ' value: ' .. v
                    end
                    if DEBUG then
                        ngx_log(ngx_err, debug_headers)
                    end
                end
                if entry['path'] ~= nil then
                    ngx.var.read_path = entry['path']
                    local real_path = ngx.unescape_uri(entry['path'])
                    local u = url.parse(real_path)
                    local host = u.host
                    local uri = u.path
                    local query = u.query
                    ngx.req.set_uri(uri)
                    ngx.req.set_uri_args(query)
                    ngx.ctx.path = uri
                    if DEBUG then
                        ngx_log(ngx_err, 'host: ' .. host)
                        ngx_log(ngx_err, 'path: ' .. real_path)
                        ngx_log(ngx_err, 'uri: ' .. uri)
                        ngx_log(ngx_err, 'ct: ' .. entry['ct'])
                        if query ~= nil then
                            ngx_log(ngx_err, 'query: ' .. json.encode(query))
                        end
                    end
                end
                if entry['method'] ~= nil then
                    if DEBUG then
                        ngx_log(ngx_err, 'method: ' .. entry['method'])
                    end
                    ngx.req.set_method(HTTP_METHOD[entry['method']])
                    ngx.ctx.method = entry['method']
                end
                if entry['body'] ~= nil then
                    if DEBUG then
                        ngx_log(ngx_err, 'body: ' .. json.encode(entry['body']))
                    end
                    ngx.req.set_body_data(json.encode(entry['body']))
                end
            end
        else
            ngx_log(ngx_err, 'decrypt is fail!')
        end
    else
        ngx_log(ngx_err, 'content decrypt is nil!')
        ngx.say('404 NOT FOUND')
        ngx.status = 404
        return
    end
end

function _M.encrypt()

    local rand_len = random.number(10, 20)
    local encrypt_key = string.sub(KEY, 1, rand_len)


    local chunk, eof = ngx.arg[1], ngx.arg[2]
    local buffered = ngx.ctx.buffered
    if not buffered then
        buffered = {}
        ngx.ctx.buffered = buffered
    end
    if chunk ~= "" and not ngx.is_subrequest then
        buffered[#buffered + 1] = chunk
        ngx.arg[1] = nil
    end
    if eof then
        local whole = table.concat(buffered)
        ngx.ctx.buffered = nil
        local encrypt_data = ''
        if whole then
            encrypt_data = ngx.encode_base64(xxtea.encrypt(whole, encrypt_key))
        end
        if DEBUG then
            ngx_log(ngx_err, encrypt_data)
            ngx_log(ngx_err, xxtea.decrypt(ngx.decode_base64(encrypt_data), encrypt_key))
        end
        ngx.arg[1] = encrypt_data .. encrypt_key .. tostring(rand_len)
    end
end

function _M.set_headers()
    ngx.header.content_length = nil
end

function _M.init_prometheus()
    prometheus = require("prometheus").init("prometheus_metrics")
    metric_requests = prometheus:counter(
        "nginx_http_requests_total", "Number of HTTP requests", { "host", "uri", "status", "method", "encrypt" })
    metric_latency = prometheus:histogram(
        "nginx_http_request_duration_seconds", "HTTP request latency", { "host", "uri", "status", "method", "encrypt" },
        { 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 5 })
    metric_connections = prometheus:gauge(
        "nginx_http_connections", "Number of HTTP connections", { "state" })
end

function _M.log_metric()
    if ngx.ctx.path ~= nil then
        metric_requests:inc(1, { ngx.var.http_host, ngx.ctx.path, ngx.var.status, ngx.ctx.method, 1 })
        metric_latency:observe(tonumber(ngx.var.request_time),
            { ngx.var.http_host, ngx.ctx.path, ngx.var.status, ngx.ctx.method, 1 })
    else
        metric_requests:inc(1, { ngx.var.http_host, ngx.var.uri, ngx.var.status, ngx.req.get_method(), 0 })
        metric_latency:observe(tonumber(ngx.var.request_time),
            { ngx.var.http_host, ngx.var.uri, ngx.var.status, ngx.req.get_method(), 0 })
    end
end

return _M
