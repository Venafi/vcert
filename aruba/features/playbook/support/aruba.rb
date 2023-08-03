# Helper method to recursively convert symbol keys to string keys
def stringify_keys(hash)
    hash.each_with_object({}) do |(key, value), new_hash|
      new_key = key.is_a?(Symbol) ? key.to_s : key
      new_value = value.is_a?(Hash) ? stringify_keys(value) : value
      new_hash[new_key] = new_value
    end
end

class Installation;
  attr_accessor :afterInstallAction
  attr_accessor :installValidationAction
  attr_accessor :capiIsNonExportable
  attr_accessor :jksAlias
  attr_accessor :jksPassword
  attr_accessor :location
  attr_accessor :file
  attr_accessor :chainFile
  attr_accessor :keyFile
  attr_accessor :format
  attr_accessor :backupFiles # will add the .bak for creating a copy of the generated file

end

class Location
  attr_accessor :instance
  attr_accessor :workload
  attr_accessor :tlsAddress
  attr_accessor :replace

end

class Subject
  attr_accessor :commonName
  attr_accessor :country
  attr_accessor :locality
  attr_accessor :organization
  attr_accessor :orgUnits
  attr_accessor :province

end

class Request
  attr_accessor :cadn
  attr_accessor :chain
  attr_accessor :csr
  attr_accessor :fields
  attr_accessor :sanDns
  attr_accessor :sanEmail
  attr_accessor :fetchPrivateKey
  attr_accessor :nickname
  attr_accessor :sanIP
  attr_accessor :issuerHint
  attr_accessor :keyCurve
  attr_accessor :keySize
  attr_accessor :keyPassword
  attr_accessor :keyType
  attr_accessor :omitSans
  attr_accessor :appInfo
  attr_accessor :sanUpn
  attr_accessor :sanUri
  attr_accessor :validDays
  attr_accessor :zone
  attr_accessor :location
  attr_accessor :subject

end

class PlaybookTask
  attr_accessor :name
  attr_accessor :renewBefore
  attr_accessor :setenvvars
  attr_accessor :installations
  attr_accessor :request

end

def object_to_hash(obj)
  if obj.is_a?(Array)
    obj.map { |item| object_to_hash(item) }
  elsif obj.is_a?(Hash)
    obj.transform_values { |value| object_to_hash(value) }
  elsif obj.is_a?(Integer) or [true, false].include? obj
    return obj
  elsif obj.is_a?(String)
    return obj
  elsif obj.is_a?(Object)
    obj.instance_variables.each_with_object({}) do |var, hash|
      key = var.to_s.delete("@")
      value = obj.instance_variable_get(var)
      hash[key] = value

      if value.is_a?(Object)
        hash[key] = object_to_hash(value) # Recursively convert nested objects to hashes
      end
    end
  else
    obj
  end
end

def request_key_should_be_string(key)
  request_string_keys = %w[cadn chain csr nickname issuerHint keyCurve keyPassword keyType appInfo validDays zone]
  request_string_keys.include?(key)
end

def request_key_should_be_integer(key)
  request_integer_keys = %w[keySize]
  request_integer_keys.include?(key)
end

def request_key_should_be_boolean(key)
  request_boolean_keys = %w[fetchPrivateKey omitSans]
  request_boolean_keys.include?(key)
end

def request_key_should_be_array_of_strings(key)
  request_array_string_keys =  %w[fields sanDns sanEmail sanIP sanUpn sanUri]
  request_array_string_keys.include?(key)
end

def request_subject_key_should_be_string(key)
  request_subject_string_keys = %w[commonName country locality organization province]
  request_subject_string_keys.include?(key)
end

def request_subject_key_should_be_array_of_strings(key)
  request_subject_array_string_keys = %w[ orgUnits ]
  request_subject_array_string_keys.include?(key)
end

def to_boolean_kv(key, value)
  case value.downcase.strip
  when 'true'
    true
  when 'false'
    false
  else
    fail(ArgumentError.new("Wrong type of value provided for key: #{key}, expected an Boolean but got: #{value}"))
  end
end

def to_boolean(value)
  case value.downcase.strip
  when 'true'
    true
  when 'false'
    false
  else
    fail(ArgumentError.new("Wrong type of value, expected an Boolean but got: #{value}"))
  end
end

def to_integer(key, value)
  integer_value = value.to_i
  if integer_value.to_s == value.strip
    integer_value
  else
    fail(ArgumentError.new("Wrong type of value provided for key: #{key}, expected an Boolean but got: #{value}"))
  end
end

def env_variable_exists_and_set(variable_name)
  if ENV[variable_name].nil?
    return false
  else
    if ENV[variable_name].to_s.empty?
      return false
    else
      return true
    end
  end
end

def validate_tpp_envs
  tpp_envs = %w[TPP_URL TPP_CN TPP_USER TPP_PASSWORD TPP_ZONE TPP_ACCESS_TOKEN TPP_ZONE_ECDSA TPP_IP TPP_TRUST_BUNDLE]

  tpp_envs.each do |tpp_env|
    unless env_variable_exists_and_set(tpp_env)
      fail(ArgumentError.new("ENV variable #{tpp_env} is not set"))
    end
  end
end

def validate_vaas_envs
  vaas_envs = %w[CLOUD_APIKEY CLOUD_ZONE]

  vaas_envs.each do |vaas_env|
    unless env_variable_exists_and_set(vaas_env)
      fail(ArgumentError.new("ENV variable #{vaas_env} is not set"))
    end
  end
end
