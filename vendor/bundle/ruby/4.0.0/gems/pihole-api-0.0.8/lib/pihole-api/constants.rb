module PiholeApi
  module Constants
    API_PATH = 'admin/api.php'
    LOGIN_PATH = 'admin/login.php'
    INDEX_PATH = 'admin'
    TELEPORTER_PATH = 'admin/scripts/pi-hole/php/teleporter.php'

    TOKEN_REGEX = /div\s+id="token"\s+hidden>([^<]+)<\/div>/
    TOKEN_SEPERATOR = ";"
  end
end
