require 'digest'

# A JKS keystore starts with the magic number 0xFEEDFEED and ends with a SHA-1
# digest of the password (UTF-16BE), the string "Mighty Aphrodite" and the rest
# of the file, so checking the digest checks both the format and the password
# without Java's keytool.
Then(/^"([^"]*)" should be jks archive with password "([^"]*)"$/) do |filename, password|
  steps %{Then a file named "#{filename}" should exist}
  data = File.binread(expand_path(filename))
  expect(data.bytesize).to be > 24
  expect(data[0, 4].unpack1('N')).to eq(0xFEEDFEED)

  body, digest = data[0...-20], data[-20..]
  expected = Digest::SHA1.digest(password.encode('UTF-16BE').b + 'Mighty Aphrodite'.b + body)
  expect(digest).to eq(expected), "#{filename} does not open with the password \"#{password}\""
end
