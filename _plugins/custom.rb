require 'net/http'
require 'json'
require 'uri'

module Jekyll
  module AssetFilter

    def get_machine_avatar(machine_name)
      root_url = "https://labs.hackthebox.com/"
      htb_token = ENV['HTB_TOKEN']

      uri = URI("#{root_url}api/v4/machine/profile/#{machine_name}")
      request = Net::HTTP::Get.new(uri)
      request['Authorization'] = "Bearer #{htb_token}"
      request['User-Agent'] = "Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0"

      res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) {|http|
        http.request(request)
      }

      begin
        url = root_url + JSON.parse(res.body)['info']['avatar']
        return "<img src='#{url}' class='avatar'>"
      rescue Exception
        return "<img src='https://labs.hackthebox.com/storage/avatars/fb2d9f98400e3c802a0d7145e125c4ff.png' class='avatar'>"
      end
    end
  end
end

Liquid::Template.register_filter(Jekyll::AssetFilter)
