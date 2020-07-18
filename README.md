# myoddweb.ssltest
Simple c# App to test supported ssl/tls version 

For example if you want to check the supported versions of google

`myoddweb.ssltest.exe --host google.com --port 443`

![myoddweb.ssltest Sample](/media/sample.png?raw=true "Ssl Test Google.com")

# SslTester Class

The SslTester class is where the test is done

`SslTester(Uri uri)` the constructor, pass the uri being tested.

Then you can test for whatever protocol you want to double check.

```
  [Flags]
  public enum SslProtocols
  {
    None = 0,
    Ssl2 = 12, // 0x0000000C
    Ssl3 = 48, // 0x00000030
    Tls = 192, // 0x000000C0
    Tls11 = 768, // 0x00000300
    Tls12 = 3072, // 0x00000C00
    Tls13 = 12288, // 0x00003000
    Default = Tls | Ssl3, // 0x000000F0
  }
```
See the [.NET code](https://referencesource.microsoft.com/#System/net/System/Net/SecureProtocols/SslEnumTypes.cs,bfabf9fcb928e856) for more details

# Note about the machine doing the query

If _your_ machine does not support Tls1.3 then the test will show "Tls13 is not supported" and this is true because _your_ machine cannot connect to it.

