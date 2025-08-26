require 'net/http'
require 'json'
require 'uri'

module Jekyll
  module AssetFilter
    def get_machine_avatar(machine_name)
      if ENV['ENV'] == 'dev'
        return "/assets/img/lame.png"
      end

      if machine_name.start_with? "HTB - "
        machine_name = machine_name.split("HTB - ")[1]
      end

      machine_name = machine_name.downcase

      return "/assets/img/#{machine_name}.png"
    end

    def machine_img(machine_name)
      return "![#{machine_name}](#{get_machine_avatar(machine_name)}){: .avatar }"
    end
  end
end

Liquid::Template.register_filter(Jekyll::AssetFilter)
