#include <cstring>

#include <array>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "abi.h"

struct ChatFilterInstance {
	const void *envoy_ptr = nullptr;
	bool is_websocket = false;
	std::string recv_buffer;
};

static std::mutex g_clients_mtx;

static std::unordered_set<ChatFilterInstance*> g_clients;

/*
 * So my gut feeling tells me html() makes Envoy cook the output
 * Do you remember YIV ?
 **/
static const char* kChatHtml = R"html(
<!DOCTYPE html>
<html>
<head><title>Envoy C++ Dynamic Module Chat</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:2rem auto;">
  <h2>Envoy C++ Dynamic Module Chat</h2>
  <div id="chat" style="border:1px solid #ccc;height:300px;overflow-y:auto;padding:10px;margin-bottom:10px;"></div>
  <input type="text" id="msg" style="width:75%;padding:8px;" placeholder="Type message..." onkeydown="if(event.key==='Enter'){send();}">
  <button onclick="send();" style="padding:8px;">Send</button>
</body>
<script>
  const chat = document.getElementById('chat');
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/chat`);
  ws.onmessage = (e) => {
    const p = document.createElement('p');
    p.textContent = e.data;
    chat.appendChild(p);
    chat.scrollTop = chat.scrollHeight;
  };
  function send() {
    const input = document.getElementById('msg');
    if (0 < input.value.trim().length) { ws.send(input.value); input.value = ''; }
  }
</script>
</html>
)html";

// Helper to wrap a text string into an unmasked RFC 6455 WebSocket frame
static std::string encode_ws_text_frame(const std::string& payload) {
	std::string frame;
	frame.push_back(static_cast<char>(0x81)); // FIN + Text opcode
	size_t len = payload.size();
	if (len <= 125) {
		frame.push_back(static_cast<char>(len));
	} else if (len <= 65535) {
		frame.push_back(126);
		frame.push_back(static_cast<char>((len >> 8) & 0xFF));
		frame.push_back(static_cast<char>(len & 0xFF));
	}
	frame.append(payload);
	return frame;
}

// Helper to decode a single masked RFC 6455 client WebSocket text frame
static bool decode_ws_text_frame(std::string &buf, std::string &out_msg) {
	if (buf.size() < 6) return false;
	uint8_t b1 = static_cast<uint8_t>(buf[1]);
	bool masked = (b1 & 0x80) != 0;
	uint64_t payload_len = b1 & 0x7F;
	size_t offset = 2;

	if (payload_len == 126) {
		if (buf.size() < 8) return false;
		payload_len = (static_cast<uint8_t>(buf[2]) << 8) | static_cast<uint8_t>(buf[3]);
		offset = 4;
	} else if (payload_len == 127) {
		return false; // Keep frames < 64KB for simplicity
	}

	if (!masked || buf.size() < offset + 4 + payload_len) return false;

	const uint8_t* mask = reinterpret_cast<const uint8_t*>(&buf[offset]);
	offset += 4;

	out_msg.resize(payload_len);
	for (size_t i = 0; i < payload_len; ++i) {
		out_msg[i] = buf[offset + i] ^ mask[i % 4];
	}
	buf.erase(0, offset + payload_len);
	return true;
}

bool compute_sec_websocket_accept(const char *, size_t, char *, size_t);

extern "C" {

envoy_dynamic_module_type_abi_version_module_ptr envoy_dynamic_module_on_program_init(void) {
  return envoy_dynamic_modules_abi_version;
}

envoy_dynamic_module_type_http_filter_config_module_ptr
envoy_dynamic_module_on_http_filter_config_new(
    envoy_dynamic_module_type_http_filter_config_envoy_ptr filter_config_envoy_ptr,
    envoy_dynamic_module_type_envoy_buffer name, envoy_dynamic_module_type_envoy_buffer config) {
  return reinterpret_cast<void*>(1);
}

void envoy_dynamic_module_on_http_filter_config_destroy(
    envoy_dynamic_module_type_http_filter_config_module_ptr filter_config_ptr) {
}
envoy_dynamic_module_type_http_filter_module_ptr envoy_dynamic_module_on_http_filter_new(
    envoy_dynamic_module_type_http_filter_config_module_ptr filter_config_ptr,
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr) {
  // Never called: on_http_filter_config_new returns null, so no filter instance is ever created.
  auto *instance = new ChatFilterInstance();
  instance->envoy_ptr = filter_config_ptr;
  return instance;
}

envoy_dynamic_module_type_on_http_filter_request_headers_status
envoy_dynamic_module_on_http_filter_request_headers(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr,
    bool end_of_stream) {

  auto *instance = static_cast<ChatFilterInstance*>(
    const_cast<void*>(filter_module_ptr));

  {
    envoy_dynamic_module_type_envoy_buffer path_buf{};
    envoy_dynamic_module_callback_http_get_header(
        filter_envoy_ptr, 
        envoy_dynamic_module_type_http_header_type_RequestHeader,
        {":path", 5},
        &path_buf,
        0,
        nullptr);
    std::string_view path(path_buf.ptr, path_buf.length);

    if (path.starts_with("/chat")) {
      instance->is_websocket = true;
#if 0
      /* PRINT ALL HEADERS */
      {
        const size_t request_headers_size = envoy_dynamic_module_callback_http_get_headers_size(
            filter_envoy_ptr,
            envoy_dynamic_module_type_http_header_type_RequestHeader
            );

        std::vector<envoy_dynamic_module_type_envoy_http_header>  request_headers(request_headers_size);

        envoy_dynamic_module_callback_http_get_headers(
            filter_envoy_ptr,
            envoy_dynamic_module_type_http_header_type_RequestHeader,
            request_headers.data());

        for (auto &header : request_headers) {
          std::cout << " - " << header.key_ptr << ": " << header.value_ptr << std::endl;
        }
      }
#endif
			std::array<char, 64> sec_websocket_accept_buf;

      {
        envoy_dynamic_module_type_envoy_buffer sec_websocket_key_buf{};
        envoy_dynamic_module_callback_http_get_header(
            filter_envoy_ptr, 
            envoy_dynamic_module_type_http_header_type_RequestHeader,
            {"sec-websocket-key", 17},
            &sec_websocket_key_buf,
            0,
            nullptr);
        std::string_view sec_websocket_key(sec_websocket_key_buf.ptr, sec_websocket_key_buf.length);
				compute_sec_websocket_accept(
						sec_websocket_key_buf.ptr,
						sec_websocket_key_buf.length,
						sec_websocket_accept_buf.data(),
						sec_websocket_accept_buf.size());
      }

      {
        std::lock_guard<std::mutex> lock(g_clients_mtx);
        g_clients.insert(instance);
      }

			std::string_view sec_websocket_accept(sec_websocket_accept_buf.data(), strlen(sec_websocket_accept_buf.data()));
      envoy_dynamic_module_type_module_http_header headers[] = {
        {":status", 7, "101", 3},
        {"connection", 10, "Upgrade", 7},
        {"sec-websocket-accept", 20, sec_websocket_accept.data(), sec_websocket_accept.size()},
        {"upgrade", 7, "websocket", 9},
      };

      envoy_dynamic_module_callback_http_send_response_headers(
          filter_envoy_ptr,
          headers,
          4,
          false);

      return envoy_dynamic_module_type_on_http_filter_request_headers_status_StopIteration;
    }
  }

  envoy_dynamic_module_type_module_http_header headers[] = {
    {"content-type", 12, "text/html; charset=utf-8", 24},
  };

  envoy_dynamic_module_callback_http_send_response(
      filter_envoy_ptr,
      200,
      headers,
      1,
      {const_cast<char*>(kChatHtml), std::strlen(kChatHtml)},
      {nullptr, 0}
      );

  /* stops the state machine */
  return envoy_dynamic_module_type_on_http_filter_request_headers_status_StopIteration;
}

envoy_dynamic_module_type_on_http_filter_request_body_status
envoy_dynamic_module_on_http_filter_request_body(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr, bool end_of_stream) {

  auto *instance = static_cast<ChatFilterInstance*>(const_cast<void*>(filter_module_ptr));

  if (!instance->is_websocket) {
    return envoy_dynamic_module_type_on_http_filter_request_body_status_Continue;
  }

  // Read incoming body vector chunks from Envoy
  const size_t vec_size = envoy_dynamic_module_callback_http_get_body_chunks_size(filter_envoy_ptr, envoy_dynamic_module_type_http_body_type_ReceivedRequestBody);

  if (vec_size > 0) {
    std::vector<envoy_dynamic_module_type_envoy_buffer> chunks(vec_size);

    envoy_dynamic_module_callback_http_get_body_chunks(
        filter_envoy_ptr,
        envoy_dynamic_module_type_http_body_type_ReceivedRequestBody,
        chunks.data());

    for (const auto &chunk : chunks) {
      instance->recv_buffer.append(chunk.ptr, chunk.length);
    }
    // Drain processed bytes from Envoy's buffer
    envoy_dynamic_module_callback_http_drain_body(
        filter_envoy_ptr,
        envoy_dynamic_module_type_http_body_type_ReceivedRequestBody,
        instance->recv_buffer.size());
  }

  // Decode any complete WebSocket frames and echo/broadcast
  std::string chat_msg;
  while (decode_ws_text_frame(instance->recv_buffer, chat_msg)) {
    std::string out_frame = encode_ws_text_frame(chat_msg);
    // Send back on the current worker stream
    envoy_dynamic_module_callback_http_send_response_data(
        filter_envoy_ptr, {out_frame.data(), out_frame.size()}, false);
  }

  return envoy_dynamic_module_type_on_http_filter_request_body_status_StopIterationAndBuffer;
}

envoy_dynamic_module_type_on_http_filter_request_trailers_status
envoy_dynamic_module_on_http_filter_request_trailers(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr) {
  return envoy_dynamic_module_type_on_http_filter_request_trailers_status_Continue;
}

envoy_dynamic_module_type_on_http_filter_response_headers_status
envoy_dynamic_module_on_http_filter_response_headers(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr, bool end_of_stream) {
  return envoy_dynamic_module_type_on_http_filter_response_headers_status_Continue;
}

envoy_dynamic_module_type_on_http_filter_response_body_status
envoy_dynamic_module_on_http_filter_response_body(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr, bool end_of_stream) {
  return envoy_dynamic_module_type_on_http_filter_response_body_status_Continue;
}

envoy_dynamic_module_type_on_http_filter_response_trailers_status
envoy_dynamic_module_on_http_filter_response_trailers(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr) {
  return envoy_dynamic_module_type_on_http_filter_response_trailers_status_Continue;
}

void envoy_dynamic_module_on_http_filter_stream_complete(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr) { }

void envoy_dynamic_module_on_http_filter_destroy(
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr) {
  auto *instance= static_cast<ChatFilterInstance*>(const_cast<void*>(filter_module_ptr));
  if (instance->is_websocket) {
    std::lock_guard<std::mutex> lock(g_clients_mtx);
    g_clients.erase(instance);
  }
  delete instance;
}

void envoy_dynamic_module_on_http_filter_http_callout_done(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr, uint64_t callout_id,
    envoy_dynamic_module_type_http_callout_result result,
    envoy_dynamic_module_type_envoy_http_header* headers, size_t headers_size,
    envoy_dynamic_module_type_envoy_buffer* body_vector, size_t body_vector_size) { }

void envoy_dynamic_module_on_http_filter_scheduled(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr, uint64_t event_id) { }

void envoy_dynamic_module_on_http_filter_downstream_above_write_buffer_high_watermark(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr) { }

void envoy_dynamic_module_on_http_filter_downstream_below_write_buffer_low_watermark(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr) { }

envoy_dynamic_module_type_on_http_filter_local_reply_status
envoy_dynamic_module_on_http_filter_local_reply(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr, uint32_t response_code,
    envoy_dynamic_module_type_envoy_buffer details, bool reset_imminent) {
  return envoy_dynamic_module_type_on_http_filter_local_reply_status_Continue;
}

void envoy_dynamic_module_on_http_filter_http_stream_headers(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr, uint64_t stream_handle,
    envoy_dynamic_module_type_envoy_http_header* headers, size_t headers_size, bool end_stream) { }

void envoy_dynamic_module_on_http_filter_http_stream_data(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr, uint64_t stream_handle,
    const envoy_dynamic_module_type_envoy_buffer* data, size_t data_count, bool end_stream) { }

void envoy_dynamic_module_on_http_filter_http_stream_trailers(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr, uint64_t stream_handle,
    envoy_dynamic_module_type_envoy_http_header* trailers, size_t trailers_size) { }

void envoy_dynamic_module_on_http_filter_http_stream_complete(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr, uint64_t stream_handle) { }

void envoy_dynamic_module_on_http_filter_http_stream_reset(
    envoy_dynamic_module_type_http_filter_envoy_ptr filter_envoy_ptr,
    envoy_dynamic_module_type_http_filter_module_ptr filter_module_ptr, uint64_t stream_handle,
    envoy_dynamic_module_type_http_stream_reset_reason reset_reason) { }

void envoy_dynamic_module_on_http_filter_config_http_callout_done(
    envoy_dynamic_module_type_http_filter_config_envoy_ptr filter_config_envoy_ptr,
    envoy_dynamic_module_type_http_filter_config_module_ptr filter_config_ptr, uint64_t callout_id,
    envoy_dynamic_module_type_http_callout_result result,
    envoy_dynamic_module_type_envoy_http_header* headers, size_t headers_size,
    envoy_dynamic_module_type_envoy_buffer* body_chunks, size_t body_chunks_size) { }

void envoy_dynamic_module_on_http_filter_config_http_stream_headers(
    envoy_dynamic_module_type_http_filter_config_envoy_ptr filter_config_envoy_ptr,
    envoy_dynamic_module_type_http_filter_config_module_ptr filter_config_ptr, uint64_t stream_id,
    envoy_dynamic_module_type_envoy_http_header* headers, size_t headers_size, bool end_stream) { }

void envoy_dynamic_module_on_http_filter_config_http_stream_data(
    envoy_dynamic_module_type_http_filter_config_envoy_ptr filter_config_envoy_ptr,
    envoy_dynamic_module_type_http_filter_config_module_ptr filter_config_ptr, uint64_t stream_id,
    const envoy_dynamic_module_type_envoy_buffer* data, size_t data_count, bool end_stream) { }

void envoy_dynamic_module_on_http_filter_config_http_stream_trailers(
    envoy_dynamic_module_type_http_filter_config_envoy_ptr filter_config_envoy_ptr,
    envoy_dynamic_module_type_http_filter_config_module_ptr filter_config_ptr, uint64_t stream_id,
    envoy_dynamic_module_type_envoy_http_header* trailers, size_t trailers_size) { }

void envoy_dynamic_module_on_http_filter_config_http_stream_complete(
    envoy_dynamic_module_type_http_filter_config_envoy_ptr filter_config_envoy_ptr,
    envoy_dynamic_module_type_http_filter_config_module_ptr filter_config_ptr, uint64_t stream_id) {
}

void envoy_dynamic_module_on_http_filter_config_http_stream_reset(
    envoy_dynamic_module_type_http_filter_config_envoy_ptr filter_config_envoy_ptr,
    envoy_dynamic_module_type_http_filter_config_module_ptr filter_config_ptr, uint64_t stream_id,
    envoy_dynamic_module_type_http_stream_reset_reason reason) {}

} // extern "C"
