def handle_http_response(response)
  case response
  when Net::HTTPSuccess
    puts "Response body: #{response.body}"
  when Net::HTTPBadRequest
    raise BadRequestError, "400 Bad Request"
  when Net::HTTPUnauthorized
    raise UnauthorizedError, "401 Unauthorized"
  when Net::HTTPNotFound
    raise NotFoundError, "404 Not Found"
  when Net::HTTPServerError
    raise ServerError, "5xx Server Error"
  else
    puts "HTTP Error: #{response.message} (#{response.code})"
  end
end
