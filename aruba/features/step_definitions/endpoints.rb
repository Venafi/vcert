#TODO: we need to rewrite aruba tests to use trust bundle instead of insecure flag
ENDPOINTS = {
    "test-mode" => "-test-mode -test-mode-delay 0",

    "TPP" => " -u '#{ENV['TPP_URL']}'" +
             " -t '#{ENV['TPP_ACCESS_TOKEN']}'" +
             " -insecure",

    "TPPdeprecated" => " -tpp-url '#{ENV['TPP_URL']}'" +
             " -tpp-user '#{ENV['TPP_USER']}'" +
             " -tpp-password '#{ENV['TPP_PASSWORD']}'" +
             " -insecure",

    "TPPecdsa" => " -u '#{ENV['TPP_URL']}'" +
             " -t '#{ENV['TPP_ACCESS_TOKEN']}'" +
             " -insecure",

    "Cloud" => "-u '#{ENV['CLOUD_URL']}' -k '#{ENV['CLOUD_APIKEY']}'",

    "VaaS" => "-u '#{ENV['CLOUD_URL']}' -k '#{ENV['CLOUD_APIKEY']}'"
}

ZONE = {
    "test-mode" => "-z Default",

    "TPP" => "-z '#{ENV['TPP_ZONE']}'",

    "TPPdeprecated" => "-z '#{ENV['TPP_ZONE']}'",

    "TPPecdsa" => "-z '#{ENV['TPP_ZONE_ECDSA']}'", 

    "Cloud" => "-z '#{ENV['CLOUD_ZONE']}'",

    "VaaS" => "-z '#{ENV['CLOUD_ZONE']}'"
}

ENDPOINT_CONFIGS = {
    "test-mode" => "
        test_mode = true
    ",
    "TPP" => "
        url = #{ENV['TPP_URL']}
        access_token = #{ENV['TPP_ACCESS_TOKEN']}
        tpp_zone = #{ENV['TPP_ZONE']}
    ",
    "TPPdeprecated" => "
        tpp_url = #{ENV['TPP_URL']}
        tpp_user = #{ENV['TPP_USER']}
        tpp_password = #{ENV['TPP_PASSWORD']}
        tpp_zone = #{ENV['TPP_ZONE']}
    ",
    "Cloud" => "
        url = #{ENV['CLOUD_URL']}
        cloud_apikey = #{ENV['CLOUD_APIKEY']}
        cloud_zone = #{ENV['CLOUD_ZONE']}
    "
}

ENDPOINT_CONFIGS["VaaS"] = ENDPOINT_CONFIGS["Cloud"]

ALL_ENDPOINTS_CONFIG = "
    [tpp-profile]
    url = #{ENV['TPP_URL']}
    access_token = #{ENV['TPP_ACCESS_TOKEN']}
    tpp_zone = #{ENV['TPP_ZONE']}

    [tpp-profile-deprecated]
    tpp_url = #{ENV['TPP_URL']}
    tpp_user = #{ENV['TPP_USER']}
    tpp_password = #{ENV['TPP_PASSWORD']}
    tpp_zone = #{ENV['TPP_ZONE']}

    [cloud-profile]
    url = #{ENV['CLOUD_URL']}
    cloud_apikey = #{ENV['CLOUD_APIKEY']}
    cloud_zone = #{ENV['CLOUD_ZONE']}

    [mock-profile]
    test_mode = true
"
