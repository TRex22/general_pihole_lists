module PiholeApi
  module AuthorisedFormEndpoints
    include ::PiholeApi::Constants

    # These endpoints need to be authorised
    # They are non API backed endpoints the require separate auth
    # https://discourse.pi-hole.net/t/pi-hole-api/1863

    def auth_form_token
      # Login
      login_response = HTTParty.post(
        "#{base_path}/#{LOGIN_PATH}",
        body: { pw: password }
      )

      @cookie = login_response.headers["set-cookie"].split(TOKEN_SEPERATOR).first

      # Index
      index_response = HTTParty.get(
        "#{base_path}/#{INDEX_PATH}",
        headers: { "Cookie": @cookie }
      )

      # Get form token
      @form_token = TOKEN_REGEX.match(index_response.body)[1]
    end

    # This does not use the API
    def teleport(whitelist: true,
      regex_whitelist: true,
      blacklist: true,
      regexlist: true,
      adlist: true,
      client: true,
      group: true,
      auditlog: true,
      staticdhcpleases: true,
      localdnsrecords: true,
      localcnamerecords: true,
      flushtables: true)

      auth_form_token unless @form_token

      # authorise_and_send(http_method:, command:, payload: {}, params: {}, custom_path: nil)
      # Content-Type: application/octet-stream
      # zip_file ; filename=""
      custom_path = "#{base_path}/#{TELEPORTER_PATH}"
      payload = {
        "token": @form_token,
        "whitelist": whitelist,
        "regex_whitelist": regex_whitelist,
        "blacklist": blacklist,
        "regexlist": regexlist,
        "adlist": adlist,
        "client": client,
        "group": group,
        "auditlog": auditlog,
        "staticdhcpleases": staticdhcpleases,
        "localdnsrecords": localdnsrecords,
        "localcnamerecords": localcnamerecords,
        "flushtables": flushtables
      }

      HTTParty.post(custom_path, body: payload, headers: { "Cookie": @cookie })
    end
  end
end
