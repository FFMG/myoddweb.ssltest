using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Authentication;
using System.Threading.Tasks;
using myoddweb.commandlineparser;
using myoddweb.commandlineparser.Rules;

namespace myoddweb.ssltest
{
  internal class Program
  {
    /// <summary>
    /// The lock we will use for wr
    /// </summary>
    private static readonly object Lock = new object();

    private static async Task Main(string[] args)
    {
      var arguments = new CommandlineParser(args, new CommandlineArgumentRules
        {
          new HelpCommandlineArgumentRule( new []{"help", "h"} ) ,
          new RequiredCommandlineArgumentRule( "host" ),
          new OptionalCommandlineArgumentRule( "port", "443" ),
          new OptionalCommandlineArgumentRule( "scheme", "http" )
      });

      var uriBuilder = new UriBuilder(arguments.Get<string>( "scheme"), 
                                      arguments.Get<string>("host"), 
                                      arguments.Get<int>( "port"));
      var uri = uriBuilder.Uri;
      var sslTest = new SslTester(uriBuilder.Uri);

      Console.WriteLine($"Checking: {uri} (IP resolved as {await sslTest.GetIpAddressAsync().ConfigureAwait(false) ?? IPAddress.None})");

      // test the prefered/expected protocols
      await TestProtocols(
        sslTest,
        "Prefered:", 
        new[] {
          SslProtocols.None,
          SslProtocols.Tls12,
          SslProtocols.Tls13
        }
        ).ConfigureAwait(false);

      // then test the obsolete protocols
      await TestProtocols(
        sslTest,
        "Obsolete:",
        new[] {
// we know it is obsolete, this is why we are testing for it
#pragma warning disable 618
          SslProtocols.Ssl2,
          SslProtocols.Ssl3,
#pragma warning restore 618
          SslProtocols.Tls,
          SslProtocols.Tls11
        }
        ).ConfigureAwait(false);
    }

    private static async Task TestProtocols(
      SslTester sslTester,
      string message,
      IEnumerable<SslProtocols> protocols
      )
    {
      Console.WriteLine( message );

      // wait for all to be done.
      await Task.WhenAll(protocols.Select(protocol => WriteResponseAsync(protocol, sslTester)).ToArray()).ConfigureAwait(false);

      // add a new line
      Console.WriteLine();
    }

    private static async Task WriteResponseAsync(SslProtocols ssl, SslTester sslTester)
    {
      var supported = await sslTester.IsSupportedAsync(ssl).ConfigureAwait(false);
      lock (Lock)
      {
        var color = Console.ForegroundColor;
        try
        {
          const string warning = "[Warning]";
          const string good    = "[Good]   ";
          const string bad     = "[Bad]    ";
          ConsoleColor newColor;
          string message;
          switch (ssl)
          {
            case SslProtocols.None:
              newColor = ConsoleColor.Blue;

              // the default is kind of pexpected
              message = supported ? good : warning; 
              break;

            // we know it is obsolete, this is why we are testing for it
#pragma warning disable 618
            case SslProtocols.Ssl2:
            case SslProtocols.Ssl3:
#pragma warning restore 618
            case SslProtocols.Tls:
            case SslProtocols.Tls11:
              newColor = supported? ConsoleColor.Yellow: ConsoleColor.Green;
              message = supported ? warning : good;
              break;

            case SslProtocols.Tls12:
            case SslProtocols.Tls13:
              newColor = supported ? ConsoleColor.Green : ConsoleColor.Red;
              message = supported ? good : warning;
              break;
            default:
              newColor = ConsoleColor.Gray;
              message = bad;
              break;
          }

          Console.ForegroundColor = newColor;
          if (supported)
          {
            Console.WriteLine($"  {message}: {ssl} is supported");
          }
          else
          {
            Console.WriteLine($"  {message}: {ssl} is not supported");
          }
        }
        finally
        {
          Console.ForegroundColor = color;
        }
      }
    }

  }
}
