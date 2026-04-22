module PiholeApi
  module UnauthorisedEndpoints
    # These endpoints dont need to be authorised
    # https://discourse.pi-hole.net/t/pi-hole-api/1863

    def type
      command = 'type'
      authorise_and_send(http_method: :get, command: command)
    end

    def version
      command = 'version'
      authorise_and_send(http_method: :get, command: command)
    end
  end
end
