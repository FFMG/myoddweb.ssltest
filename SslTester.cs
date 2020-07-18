using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace myoddweb.ssltest
{
  public class SslTester
  {
    #region Member variables
    /// <summary>
    /// If the url given is valid or not
    /// </summary>
    private bool _isValid;

    /// <summary>
    /// The data lock
    /// </summary>
    private readonly SemaphoreSlim _lock = new SemaphoreSlim(1,1);

    /// <summary>
    /// The ssl protocols lock;
    /// </summary>
    private readonly object _sslProtocolsLock = new object();

    /// <summary>
    /// The supported protocols
    /// </summary>
    private SslProtocols _sslProtocols;

    /// <summary>
    /// the given uri
    /// </summary>
    private readonly Uri _uri;

    /// <summary>
    /// The IP endpoint
    /// </summary>
    private IPEndPoint _endPoint;

    /// <summary>
    /// If the values have been initialised.
    /// </summary>
    private bool _initialised;
    #endregion

    /// <summary>
    /// The constructor
    /// </summary>
    /// <param name="uri"></param>
    public SslTester(Uri uri)
    {
      _uri = uri ?? throw new ArgumentNullException(nameof(uri));
    }

    /// <summary>
    /// Check if the data is valid or not
    /// </summary>
    /// <returns></returns>
    public async Task<bool> IsValidAsync()
    {
      await InitialiseAsync().ConfigureAwait(false);
      return _isValid;
    }

    /// <summary>
    /// Test if a given protocol is supported.
    /// </summary>
    /// <param name="ssl"></param>
    /// <returns></returns>
    public async Task<bool> IsSupportedAsync(SslProtocols ssl)
    {
      await InitialiseAsync().ConfigureAwait( false );
      lock (_sslProtocolsLock)
      {
        return _sslProtocols.HasFlag(ssl);
      }
    }

    /// <summary>
    /// Get the IPAddress or null
    /// </summary>
    /// <returns></returns>
    public async Task<IPAddress> GetIpAddressAsync()
    {
      await InitialiseAsync().ConfigureAwait(false);
      await _lock.WaitAsync().ConfigureAwait(false);
      try
      {
        var endpoint = await GetEndPointAsyncInLock().ConfigureAwait(false);
        return endpoint?.Address;
      }
      finally
      {
        _lock.Release();
      }
    }

    #region Private methods
    /// <summary>
    /// Get the endpoint
    /// </summary>
    /// <returns></returns>
    private async Task<IPEndPoint> GetEndPointAsyncInLock()
    {
      try
      {
        if (null != _endPoint || _initialised )
        {
          return _endPoint;
        }

        // get the ip info.
        var ipHostInfo = await Dns.GetHostEntryAsync(_uri.Host).ConfigureAwait(false);
        var ipAddress = ipHostInfo.AddressList[0];
        _endPoint = new IPEndPoint(ipAddress, _uri.Port);
      }
      catch
      {
        // yes, setting this value to null will cause
        // this function to be called again and again
        _endPoint = null;
      }

      return _endPoint;
    }

    /// <summary>
    /// Initialise the 
    /// </summary>
    private async Task InitialiseAsync()
    {
      if (_initialised)
      {
        return;
      }

      await _lock.WaitAsync().ConfigureAwait(false);
      try
      {
        // get the endpoint
        var endPoint = await GetEndPointAsyncInLock().ConfigureAwait( false );
        if (null == endPoint)
        {
          _isValid = false;
          return;
        }

        // list of protocols
        var sslProtocols = (SslProtocols[]) Enum.GetValues(typeof(SslProtocols));

        // the list of taks
        var tasks = new List<Task>(sslProtocols.Length);

        // then add all the tasks for each and every protocols.
        tasks.AddRange(sslProtocols.Select(sslProtocol => TrySslAsync(endPoint, _uri, sslProtocol)));

        // then wait for them all to end
        await Task.WhenAll(tasks.ToArray()).ConfigureAwait(false);

        // if we made it here then it is valid
        _isValid = true;
      }
      catch
      {
        _isValid = false;
      }
      finally
      {
        // either way, it has been initialised.
        _initialised = true;
        _lock.Release();
      }
    }

    /// <summary>
    /// Try the given protocols and see if it is valid.
    /// </summary>
    /// <param name="endPoint"></param>
    /// <param name="uri"></param>
    /// <param name="sslProtocol"></param>
    /// <returns></returns>
    private async Task TrySslAsync(EndPoint endPoint, Uri uri, SslProtocols sslProtocol)
    {
      var socket = new Socket(endPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
      await socket.ConnectAsync(endPoint).ConfigureAwait(false);
      try
      {
        await using Stream networkStream = new NetworkStream(socket);
        await using var sslStream = new SslStream(networkStream, false, ValidateServerCertificate, null);
        try
        {
          var task = sslStream.AuthenticateAsClientAsync(uri.Host,
            null,
            sslProtocol,
            true);

          // if we timeout we will asume that it is not supported.
          if (await Task.WhenAny(task, Task.Delay(1000)) == task)
          {
            lock (_sslProtocolsLock)
            {
              _sslProtocols |= sslStream.SslProtocol;
            }
          }
        }
        catch
        {
          // this protocol is not supported.
        }
      }
      finally
      {
        // close the socket
        socket.Close();
      }
    }

    private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslpolicyerrors)
    {
      return true;
    }
    #endregion
  }
}
