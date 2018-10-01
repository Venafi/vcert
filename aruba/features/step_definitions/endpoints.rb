
ENDPOINTS = {
    "test-mode" => "-test-mode -test-mode-delay 0",

    "TPP" => " -tpp-url      '#{ENV['VCERT_TPP_URL']}'      " +
             " -tpp-user     '#{ENV['VCERT_TPP_USER']}'     " +
             " -tpp-password '#{ENV['VCERT_TPP_PASSWORD']}' " +
             " -z            '#{ENV['VCERT_TPP_ZONE']}'     " +
             " -insecure",

    "Cloud" => "-venafi-saas-url '#{ENV['VCERT_CLOUD_URL']}' -k '#{ENV['VCERT_CLOUD_APIKEY']}' -z '#{ENV['VCERT_CLOUD_ZONE']}'"
}

ENDPOINT_CONFIGS = {
    "test-mode" => "
        test_mode = true
    ",
    "TPP" => "
        tpp_url = #{ENV['VCERT_TPP_URL']}
        tpp_user = #{ENV['VCERT_TPP_USER']}
        tpp_password = #{ENV['VCERT_TPP_PASSWORD']}
        tpp_zone = #{ENV['VCERT_TPP_ZONE']}
    ",
    "Cloud" => "
        cloud_url = #{ENV['VCERT_CLOUD_URL']}
        cloud_apikey = #{ENV['VCERT_CLOUD_APIKEY']}
        cloud_zone = #{ENV['VCERT_CLOUD_ZONE']}
    "
}

ALL_ENDPOINTS_CONFIG = "
    [tpp-profile]
    tpp_url = #{ENV['VCERT_TPP_URL']}
    tpp_user = #{ENV['VCERT_TPP_USER']}
    tpp_password = #{ENV['VCERT_TPP_PASSWORD']}
    tpp_zone = #{ENV['VCERT_TPP_ZONE']}

    [cloud-profile]
    cloud_url = #{ENV['VCERT_CLOUD_URL']}
    cloud_apikey = #{ENV['VCERT_CLOUD_APIKEY']}
    cloud_zone = #{ENV['VCERT_CLOUD_ZONE']}

    [mock-profile]
    test_mode = true
"