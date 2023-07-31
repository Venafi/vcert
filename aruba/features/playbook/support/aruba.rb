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
  attr_accessor :capiIsNonExportable
  attr_accessor :jksAlias
  attr_accessor :jksPassword
  attr_accessor :location
  attr_accessor :pemCertFilename
  attr_accessor :pemChainFilename
  attr_accessor :pemKeyFilename
  attr_accessor :type

  def initialize
    @capiIsNonExportable=false
  end
end

class Location
  attr_accessor :instance
  attr_accessor :tlsAddress
  attr_accessor :replace

  def initialize
    @replace=false
  end
end

class Subject
  attr_accessor :commonName
  attr_accessor :country
  attr_accessor :locality
  attr_accessor :organization
  attr_accessor :orgUnits
  attr_accessor :province

  def initialize
    @orgUnits = Array.new
  end
end

class Request
  attr_accessor :cadn
  attr_accessor :chainOption
  attr_accessor :csrOrigin
  attr_accessor :customFields
  attr_accessor :dnsNames
  attr_accessor :emails
  attr_accessor :fetchPrivateKey
  attr_accessor :friendlyName
  attr_accessor :ips
  attr_accessor :issuerHint
  attr_accessor :keyCurve
  attr_accessor :keyLength
  attr_accessor :keyPassword
  attr_accessor :keyType
  attr_accessor :omitSans
  attr_accessor :origin
  attr_accessor :upns
  attr_accessor :uris
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

  def initialize
    @installations = []
    @request = Request
  end
end

def objects_to_hashes(objects)
  objects.map { |obj| obj.instance_variables.each_with_object({}) { |var, hash| hash[var.to_s.delete("@")] = obj.instance_variable_get(var) } }
end

def object_to_hash(obj)
  obj.instance_variables.each_with_object({}) do |var, hash|
    key = var.to_s.delete("@")
    value = obj.instance_variable_get(var)
    hash[key] = value
  end
end



def request_key_should_be_string(key)
  request_string_keys= %w[cadn chainOption csrOrigin friendlyName issuerHint keyCurve keyPassword keyType origin validDays zone]
  request_string_keys.include?(key)
end

def request_key_should_be_integer(key)
  request_integer_keys= %w[keyLength]
  request_integer_keys.include?(key)
end

def request_key_should_be_boolean(key)
  request_boolean_keys= %w[fetchPrivateKey omitSans]
  request_boolean_keys.include?(key)
end

def request_key_should_be_array_of_strings(key)
  request_array_string_keys=  %w[dnsNames emails ips upns uris]
  request_array_string_keys.include?(key)
end

def to_boolean(key, value)
  case value.downcase.strip
  when 'true'
    true
  when 'false'
    false
  else
    fail(ArgumentError.new("Wrong type of value provided for key: #{key}, expected an Boolean but got: #{value}"))
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