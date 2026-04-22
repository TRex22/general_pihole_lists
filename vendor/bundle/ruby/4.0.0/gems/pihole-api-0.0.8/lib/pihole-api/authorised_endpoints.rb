module PiholeApi
  module AuthorisedEndpoints
    # These endpoints need to be authorised
    # https://discourse.pi-hole.net/t/pi-hole-api/1863

    def summary_raw
      command = "summaryRaw&auth=#{password}"
      authorise_and_send(http_method: :get, command: command)
    end

    def summary(params: {})
      command = 'summary'
      authorise_and_send(http_method: :get, command: command, params: params)
    end

    def over_time_data_10_mins
      command = 'overTimeData10mins'
      authorise_and_send(http_method: :get, command: command)
    end

    def top_items(number_of_items=10)
      command = "topItems=#{number_of_items}"
      authorise_and_send(http_method: :get, command: command)
    end

    def get_query_sources(number_of_items=10)
      command = "getQuerySources=#{number_of_items}"
      authorise_and_send(http_method: :get, command: command)
    end

    def top_clients(number_of_items=10)
      command = "topClients=#{number_of_items}"
      authorise_and_send(http_method: :get, command: command)
    end

    def get_forward_destinations
      command = 'getForwardDestinations'
      authorise_and_send(http_method: :get, command: command)
    end

    def get_query_types
      command = 'getQueryTypes'
      authorise_and_send(http_method: :get, command: command)
    end

    def get_all_queries(params: {}, from_time: nil, until_time: nil, latest_number_of_items: nil)
      # API version 3:
      # First column: Timestamp of query
      # Second column: Type of query (IPv4 or IPv6)
      # Third column: Requested domain name
      # Fourth column: Requesting client
      # Fifth column: Answer type (1 = blocked by gravity.list, 2 = forwarded to upstream server, 3 = answered by local cache, 4 = blocked by wildcard blocking)

      if latest_number_of_items
        command = "getAllQueries=#{latest_number_of_items}"
      else
        command = 'getAllQueries'
      end

      if from_time
        command = "#{command}&from=#{from_time.to_i}&until=#{until_time.to_i}"
      end

      authorise_and_send(http_method: :get, command: command, params: params)
    end

    def recent_blocked
      command = 'recentBlocked'
      authorise_and_send(http_method: :get, command: command)
    end

    def enable
      command = 'enable'
      authorise_and_send(http_method: :get, command: command)
    end

    def disable
      command = 'disable'
      authorise_and_send(http_method: :get, command: command)
    end
  end
end
