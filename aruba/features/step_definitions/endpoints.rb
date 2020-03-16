#TODO: we need to rewrite aruba tests to use trust bundle instead of insecure flag
ENDPOINTS = {
    "test-mode" => "-test-mode -test-mode-delay 0",

    "TPP" => " -u      '#{ENV['VCERT_TPP_URL']}'      " +
             " -t     '#{ENV['TPPACCESS_TOKEN']}'     " +
             " -z            '#{ENV['VCERT_TPP_ZONE']}'     " +
             " -insecure",

    "TPPdeprecated" => " -tpp-url      '#{ENV['VCERT_TPP_URL']}'      " +
             " -tpp-user     '#{ENV['VCERT_TPP_USER']}'     " +
             " -tpp-password '#{ENV['VCERT_TPP_PASSWORD']}' " +
             " -z            '#{ENV['VCERT_TPP_ZONE']}'     " +
             " -insecure",

    "TPPecdsa" => " -u      '#{ENV['VCERT_TPP_URL']}'      " +
             " -t     '#{ENV['TPPACCESS_TOKEN']}'     " +
             " -z            '#{ENV['TPPZONE_ECDSA']}'     " +
             " -insecure",

    "Cloud" => "-u '#{ENV['VCERT_CLOUD_URL']}' -k '#{ENV['VCERT_CLOUD_APIKEY']}' -z '#{ENV['VCERT_CLOUD_ZONE']}'"
}

ENDPOINT_CONFIGS = {
    "test-mode" => "
        test_mode = true
    ",
    "TPP" => "
        url = #{ENV['VCERT_TPP_URL']}
        access_token = #{ENV['TPPACCESS_TOKEN']}
        tpp_zone = #{ENV['VCERT_TPP_ZONE']}
    ",
    "TPPdeprecated" => "
        tpp_url = #{ENV['VCERT_TPP_URL']}
        tpp_user = #{ENV['VCERT_TPP_USER']}
        tpp_password = #{ENV['VCERT_TPP_PASSWORD']}
        tpp_zone = #{ENV['VCERT_TPP_ZONE']}
    ",
    "Cloud" => "
        url = #{ENV['VCERT_CLOUD_URL']}
        cloud_apikey = #{ENV['VCERT_CLOUD_APIKEY']}
        cloud_zone = #{ENV['VCERT_CLOUD_ZONE']}
    "
}

ALL_ENDPOINTS_CONFIG = "
    [tpp-profile]
    url = #{ENV['VCERT_TPP_URL']}
    access_token = #{ENV['TPPACCESS_TOKEN']}
    tpp_zone = #{ENV['VCERT_TPP_ZONE']}

    [tpp-profile-deprecated]
    tpp_url = #{ENV['VCERT_TPP_URL']}
    tpp_user = #{ENV['VCERT_TPP_USER']}
    tpp_password = #{ENV['VCERT_TPP_PASSWORD']}
    tpp_zone = #{ENV['VCERT_TPP_ZONE']}

    [cloud-profile]
    url = #{ENV['VCERT_CLOUD_URL']}
    cloud_apikey = #{ENV['VCERT_CLOUD_APIKEY']}
    cloud_zone = #{ENV['VCERT_CLOUD_ZONE']}

    [mock-profile]
    test_mode = true
"