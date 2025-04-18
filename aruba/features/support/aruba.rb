require 'aruba/cucumber'
require "json_spec/cucumber"

Aruba.configure do |config|
  config.allow_absolute_paths = true
end

PREFIX_CN = "vcert"

PLATFORM_TPP = "TPP"
PLATFORM_VAAS = "VaaS" # places already use it as is
PLATFORM_VCP = "VCP"
PLATFORM_FIREFLY = "Firefly"

PATH_SEPARATOR = "/"
TEMP_PATH = "tmp/aruba"

KEYSTORE_TYPE_AWS = "AWS"
KEYSTORE_TYPE_AZURE = "AZURE"
KEYSTORE_TYPE_GCP = "GOOGLE"

GCP_KEYSTORE_ID = ENV["GCP_KEYSTORE_ID"]
GCP_KEYSTORE_NAME = ENV["GCP_KEYSTORE_NAME"]
GCP_PROVIDER_NAME = ENV["GCP_PROVIDER_NAME"]

AWS_KEYSTORE_ID = ENV["AWS_KEYSTORE_ID"]
AWS_KEYSTORE_NAME = ENV["AWS_KEYSTORE_NAME"]
AWS_PROVIDER_NAME = ENV["AWS_PROVIDER_NAME"]

AZURE_KEYSTORE_ID = ENV["AZURE_KEYSTORE_ID"]
AZURE_KEYSTORE_NAME = ENV["AZURE_KEYSTORE_NAME"]
AZURE_PROVIDER_NAME = ENV["AZURE_PROVIDER_NAME"]

DUMMY_PASSWORD = "CyberArkT3stP4ZZC0de%jQX^J=4H"

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
