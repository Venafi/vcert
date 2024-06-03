require 'aruba/cucumber'
require "json_spec/cucumber"

Aruba.configure do |config|
  config.allow_absolute_paths = true
end

$prefix_cn = "vcert"

$platform_tpp = "TPP"
$platform_vaas = "VaaS" # places already use it as is
$platform_vcp = "VCP"
$platform_firefly = "Firefly"

$path_separator = "/"
$temp_path = "tmp/aruba"

$keystore_type_aws = "AWS"
$keystore_type_azure = "AZURE"
$keystore_type_gcp = "GOOGLE"

$gcp_keystore_id = ENV["GCP_KEYSTORE_ID"]
$gcp_keystore_name = ENV["GCP_KEYSTORE_NAME"]
$gcp_provider_name = ENV["GCP_PROVIDER_NAME"]

def last_json
  last_command_started.stdout.to_s
end

def random_cn
  Time.now.to_i.to_s + "-" + (0..4).to_a.map{|a| rand(36).to_s(36)}.join + ".venafi.example.com"
end

def random_string
  Time.now.to_i.to_s + "-" + (0..4).to_a.map{|a| rand(36).to_s(36)}.join
end

def random_filename
  Time.now.to_i.to_s + "-" + (0..6).to_a.map{|a| rand(36).to_s(36)}.join + ".txt"
end

class Stack
  def initialize
    @data = []
  end

  def push(item)
    @data.push(item)
  end

  def pop
    @data.pop
  end

  def peek
    @data.last
  end

  def empty?
    @data.empty?
  end

  def size
    @data.size
  end
end

def extract_json_from_output(input_string)
  stack = Stack.new

  start_index = 0
  end_index = 0
  popped_item = 0
  input_string.each_char.with_index do |char, index|
    if char == "{"
      stack.push(index)
    end
    if char == "}"
      popped_item = stack.pop
    end
    if stack.empty?
      start_index = popped_item
      end_index = index
      break
    end
  end

  if start_index && end_index && start_index < end_index
    extracted_substring = input_string[start_index-1 + 1...end_index+1]
    return extracted_substring
  else
    fail(ArgumentError.new("Unabel to get JSON from string: #{input_string}"))
  end
end
