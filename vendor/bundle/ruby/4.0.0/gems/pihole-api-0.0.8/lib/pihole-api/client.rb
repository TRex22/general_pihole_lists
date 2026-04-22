module PiholeApi
  class Client
    include ::PiholeApi::Constants

    # Endpoints
    include ::PiholeApi::UnauthorisedEndpoints
    include ::PiholeApi::AuthorisedEndpoints
    include ::PiholeApi::AuthorisedFormEndpoints

    attr_reader :password, :api_token, :form_token, :cookie, :base_path, :port

    def initialize(base_path:, password:, port: 80)
      @password = password
      @api_token = PiholeApi::Client.hash_password(password)

      @base_path = base_path
      @port = port
    end

    def self.compatible_api_version
      'v3'
    end

    # This is the version of the API docs this client was built off-of
    def self.api_version
      'v2 2023-01-21'
    end

    def self.hash_password(password)
      require 'digest'

      hash1 = Digest::SHA256.hexdigest(password)
      Digest::SHA256.hexdigest(hash1) # Use as hash password for client
    end

    private

    def authorise_and_send(http_method:, command:, payload: {}, params: {})
      start_time = micro_second_time_now

      if params.nil? || params.empty?
        params = {}
      end

      response = HTTParty.send(
        http_method.to_sym,
        construct_base_path(command, params),
        body: payload,
        headers: {
          'Access-Token': @access_token,
          'Content-Type': 'application/json',
          "Accept": 'application/json',
          "X-Pi-hole-Authenticate": api_token
        },
        port: port,
        format: :json
      )

      end_time = micro_second_time_now
      construct_response_object(response, command, start_time, end_time)
    end

    def construct_response_object(response, path, start_time, end_time)
      {
        'body' => parse_body(response, path),
        'headers' => response.headers,
        'metadata' => construct_metadata(response, start_time, end_time)
      }
    end

    def construct_metadata(response, start_time, end_time)
      total_time = end_time - start_time

      {
        'start_time' => start_time,
        'end_time' => end_time,
        'total_time' => total_time
      }
    end

    def body_is_present?(response)
      !body_is_missing?(response)
    end

    def body_is_missing?(response)
      response.body.nil? || response.body.empty?
    end

    def parse_body(response, path)
      return [] if response.body == "[]"
      parse_json(response) # Purposely not using HTTParty
    end

    def parse_json(response)
      begin
        JSON.parse(response.body)
      rescue => _e
        response.body
      end
    end

    def micro_second_time_now
      (Time.now.to_f * 1_000_000).to_i
    end

    def construct_base_path(command, params)
      constructed_path = "#{base_path}/#{API_PATH}?#{command}&auth=#{api_token}"

      if params == {}
        constructed_path
      else
        "#{constructed_path}&#{process_params(params)}"
      end
    end

    def process_params(params)
      params.keys.map { |key| "#{key}=#{params[key]}" }.join('&')
    end

    def process_cursor(cursor, params: {})
      unless cursor.nil? || cursor.empty?
        params['cursor'] = cursor
      end

      params
    end
  end
end
