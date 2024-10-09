using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RuntimeCommon;
using System.Reflection;

#if DEBUG
var mda = new MeasureDifferentAlgorithms();
mda.JsonWebTokenHandlerValidateTokenRsa256();
mda.JsonWebTokenHandlerValidateTokenRsa256();
#else
//BenchmarkDotNet.Running.BenchmarkRunner.Run(Assembly.GetExecutingAssembly());
BenchmarkDotNet.Running.BenchmarkRunner.Run<MeasureThroughput>();
#endif

//---

[SimpleJob(launchCount: 2, warmupCount: 0, iterationCount: 3, invocationCount: 1)]
public class MeasureThroughput
{
    private JsonWebTokenHandler _jsonWebTokenHandler = new();
    private List<(string, TokenValidationParameters)> _inputParameters = new();

    private void TestTokenSignedWith(SigningCredentials signingCredentials)
    {
        _inputParameters.Add((
            _jsonWebTokenHandler.CreateToken(TestData.SecurityTokenDescriptor(signingCredentials)),
            TestData.TokenValidationParameters(signingCredentials.Key)
        ));
    }

    public MeasureThroughput()
    {
        TestTokenSignedWith(TestData.RsaSigningCredentials_2048Sha256);
        TestTokenSignedWith(TestData.RsaSigningCredentials_2048Sha512);
        TestTokenSignedWith(TestData.SymmetricSigningCreds_256Sha256);

#if NET47_OR_GREATER || !NETFRAMEWORK
        TestTokenSignedWith(TestData.EcdSigningCredentials_2048Sha256);
        TestTokenSignedWith(TestData.EcdSigningCredentials_2048Sha512);
#endif
    }

    public IEnumerable<(string, TokenValidationParameters)> InputParameters => _inputParameters;

    [ParamsSource(nameof(InputParameters))]
    public (string, TokenValidationParameters) TokenAndValidationParams { get; set; }

    [Benchmark]
    public void HundredThousandOneThread()
    {
        var (token, tvp) = TokenAndValidationParams;

        for (var i = 0; i < 100_000; i++)
        {
            _jsonWebTokenHandler.ValidateToken(token, tvp);
        }
    }

    [Benchmark]
    public void HundredThousandFourThreads()
    {
        var (token, tvp) = TokenAndValidationParams;

        var quarter = () =>
        {
            for (var i = 0; i < 25_000; i++)
            {
                _jsonWebTokenHandler.ValidateToken(token, tvp);
            }
        };
        Parallel.Invoke(quarter, quarter, quarter, quarter);
    }
}

//---

public class MeasureDifferentAlgorithms
{
#if NET47_OR_GREATER || !NETFRAMEWORK
    private string _jwtTokenEcd256;
    private string _jwtTokenEcd512;

    private TokenValidationParameters _tokenValidationParametersEcd256;
    private TokenValidationParameters _tokenValidationParametersEcd512;
#endif

    private string _jwtTokenRsa256;
    private string _jwtTokenRsa512;
    private string _jwtTokenSymmetric256;

    private TokenValidationParameters _tokenValidationParametersRsa256;
    private TokenValidationParameters _tokenValidationParametersRsa512;
    private TokenValidationParameters _tokenValidationParametersSymmetric256;

    private JsonWebTokenHandler _jsonWebTokenHandler = new JsonWebTokenHandler();

    public MeasureDifferentAlgorithms()
    {
        IdentityModelEventSource.ShowPII = true;
        CryptoProviderFactory.DefaultCacheSignatureProviders = false;

#if NET47_OR_GREATER || !NETFRAMEWORK
        _jwtTokenEcd256 = _jsonWebTokenHandler.CreateToken(TestData.SecurityTokenDescriptor(TestData.EcdSigningCredentials_2048Sha256));
        _jwtTokenEcd512 = _jsonWebTokenHandler.CreateToken(TestData.SecurityTokenDescriptor(TestData.EcdSigningCredentials_2048Sha512));

        _tokenValidationParametersEcd256 = TestData.TokenValidationParameters(TestData.EcdSigningCredentials_2048Sha256.Key);
        _tokenValidationParametersEcd512 = TestData.TokenValidationParameters(TestData.EcdSigningCredentials_2048Sha512.Key);
#endif

        _jwtTokenRsa256 = _jsonWebTokenHandler.CreateToken(TestData.SecurityTokenDescriptor(TestData.RsaSigningCredentials_2048Sha256));
        _jwtTokenRsa512 = _jsonWebTokenHandler.CreateToken(TestData.SecurityTokenDescriptor(TestData.RsaSigningCredentials_2048Sha512));
        _jwtTokenSymmetric256 = _jsonWebTokenHandler.CreateToken(TestData.SecurityTokenDescriptor(TestData.SymmetricSigningCreds_256Sha256));

        _tokenValidationParametersRsa256 = TestData.TokenValidationParameters(TestData.RsaSigningCredentials_2048Sha512.Key);
        _tokenValidationParametersRsa512 = TestData.TokenValidationParameters(TestData.RsaSigningCredentials_2048Sha512.Key);
        _tokenValidationParametersSymmetric256 = TestData.TokenValidationParameters(TestData.SymmetricSigningCreds_256Sha256.Key);
    }

#if NET47_OR_GREATER || !NETFRAMEWORK
    [Benchmark]
    public void JsonWebTokenHandlerValidateTokenEcd256()
    {
        _jsonWebTokenHandler.ValidateToken(_jwtTokenEcd256, _tokenValidationParametersEcd256);
    }

    [Benchmark]
    public void JsonWebTokenHandlerValidateTokenEcd512()
    {
        _jsonWebTokenHandler.ValidateToken(_jwtTokenEcd512, _tokenValidationParametersEcd512);
    }
#endif

    [Benchmark]
    public void JsonWebTokenHandlerValidateTokenRsa256()
    {
        _jsonWebTokenHandler.ValidateToken(_jwtTokenRsa256, _tokenValidationParametersRsa256);
    }

    [Benchmark]
    public void JsonWebTokenHandlerValidateTokenRsa512()
    {
        _jsonWebTokenHandler.ValidateToken(_jwtTokenRsa512, _tokenValidationParametersRsa512);
    }
    [Benchmark]

    public void JsonWebTokenHandlerValidateTokenSymmetric256()
    {
        _jsonWebTokenHandler.ValidateToken(_jwtTokenSymmetric256, _tokenValidationParametersSymmetric256);
    }
}

//---

#if FALSE
[MediumRunJob]
public class JwtValidation
{
    private readonly string _token;
    private readonly TokenValidationParameters _tvpDefault, _tvpCsp;
    private readonly JsonWebTokenHandler _jwtHandler;

    public JwtValidation()
    {
        var key = JsonWebKey.Create("""{"kty":"RSA","use":"sig","kid":"-KI3Q9nNR7bRofxmeZoXqbHZGew","x5t":"-KI3Q9nNR7bRofxmeZoXqbHZGew","n":"tJL6Wr2JUsxLyNezPQh1J6zn6wSoDAhgRYSDkaMuEHy75VikiB8wg25WuR96gdMpookdlRvh7SnRvtjQN9b5m4zJCMpSRcJ5DuXl4mcd7Cg3Zp1C5-JmMq8J7m7OS9HpUQbA1yhtCHqP7XA4UnQI28J-TnGiAa3viPLlq0663Cq6hQw7jYo5yNjdJcV5-FS-xNV7UHR4zAMRruMUHxte1IZJzbJmxjKoEjJwDTtcd6DkI3yrkmYt8GdQmu0YBHTJSZiz-M10CY3LbvLzf-tbBNKQ_gfnGGKF7MvRCmPA_YF_APynrIG7p4vPDRXhpG3_CIt317NyvGoIwiv0At83kQ","e":"AQAB","x5c":["MIIDBTCCAe2gAwIBAgIQGQ6YG6NleJxJGDRAwAd/ZTANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIyMTAwMjE4MDY0OVoXDTI3MTAwMjE4MDY0OVowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALSS+lq9iVLMS8jXsz0IdSes5+sEqAwIYEWEg5GjLhB8u+VYpIgfMINuVrkfeoHTKaKJHZUb4e0p0b7Y0DfW+ZuMyQjKUkXCeQ7l5eJnHewoN2adQufiZjKvCe5uzkvR6VEGwNcobQh6j+1wOFJ0CNvCfk5xogGt74jy5atOutwquoUMO42KOcjY3SXFefhUvsTVe1B0eMwDEa7jFB8bXtSGSc2yZsYyqBIycA07XHeg5CN8q5JmLfBnUJrtGAR0yUmYs/jNdAmNy27y83/rWwTSkP4H5xhihezL0QpjwP2BfwD8p6yBu6eLzw0V4aRt/wiLd9ezcrxqCMIr9ALfN5ECAwEAAaMhMB8wHQYDVR0OBBYEFJcSH+6Eaqucndn9DDu7Pym7OA8rMA0GCSqGSIb3DQEBCwUAA4IBAQADKkY0PIyslgWGmRDKpp/5PqzzM9+TNDhXzk6pw8aESWoLPJo90RgTJVf8uIj3YSic89m4ftZdmGFXwHcFC91aFe3PiDgCiteDkeH8KrrpZSve1pcM4SNjxwwmIKlJdrbcaJfWRsSoGFjzbFgOecISiVaJ9ZWpb89/+BeAz1Zpmu8DSyY22dG/K6ZDx5qNFg8pehdOUYY24oMamd4J2u2lUgkCKGBZMQgBZFwk+q7H86B/byGuTDEizLjGPTY/sMms1FAX55xBydxrADAer/pKrOF1v7Dq9C1Z9QVcm5D9G4DcenyWUdMyK43NXbVQLPxLOng51KO9icp2j4U7pwHP"],"issuer":"https://login.microsoftonline.com/{tenantid}/v2.0"}""");
        var keyRsaParameters = new RSAParameters()
        {
            Exponent = Base64UrlEncoder.DecodeBytes(key.E),
            Modulus = Base64UrlEncoder.DecodeBytes(key.N),
        };

        var tvp = new TokenValidationParameters();
        tvp.ValidateLifetime = false;
        tvp.ValidAudience = "https://api.spaces.skype.com";
        tvp.ValidIssuer = "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/";

        _tvpDefault = tvp.Clone();
        var rsaDefault = RSA.Create(keyRsaParameters);
        _tvpDefault.IssuerSigningKeys = new[]
        {
            new RsaSecurityKey(rsaDefault) { KeyId = key.KeyId },
        };

        _tvpCsp = tvp.Clone();
        var rsaCsp = new RSACryptoServiceProvider();
        rsaCsp.ImportParameters(keyRsaParameters);
        _tvpCsp.IssuerSigningKeys = new[]
        {
            new RsaSecurityKey(rsaCsp) { KeyId = key.KeyId },
        };

        _token = getSampleToken();

        _jwtHandler = new JsonWebTokenHandler();
    }

    private static string getSampleToken()
    {
        var token = "eyJ0eXAiOiJKV1QiLCJub25jZSI6IndsV1JFTDdGakYxZno1dFJ0ZFZTazdScHY4djdRQWhXWWxtdzlDajVReTAiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1LSTNROW5OUjdiUm9meG1lWm9YcWJIWkdldyIsImtpZCI6Ii1LSTNROW5OUjdiUm9meG1lWm9YcWJIWkdldyJ9.eyJhdWQiOiJodHRwczovL2FwaS5zcGFjZXMuc2t5cGUuY29tIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3LyIsImlhdCI6MTY4NzgxNzA3NCwibmJmIjoxNjg3ODE3MDc0LCJleHAiOjE2ODc4MjI0OTIsImFjY3QiOjAsImFjciI6IjEiLCJhaW8iOiJBWFFBaS84VEFBQUFleUdUWVBxU3ZOTFBXUWFVZGpqYjlDd0w5eVRkOUhlSmUxZGxValRvZTRFTlZZQnh2azZRY2ZyWFFaVm5tN3JyZ0lrV1ZPaGN4S2ZKTmUyNE5yTXVmTUtGL25ROXdMQzIwZGZYZTgxUlhtMWRzYUVyMTFoSGNmZCtKK01zaUFyZ2FYeGNNREpRcEowMi8vK0tBZzJLM0E9PSIsImFtciI6WyJyc2EiLCJtZmEiXSwiYXBwaWQiOiI1ZTNjZTZjMC0yYjFmLTQyODUtOGQ0Yi03NWVlNzg3ODczNDYiLCJhcHBpZGFjciI6IjAiLCJhdXRoX3RpbWUiOjE2ODc4MDQyMTIsImNhcG9saWRzX2xhdGViaW5kIjpbIjU5NTZmZjVhLTZmZGItNDc3ZS05ZDRkLTlmN2QyNjJlNjk0YSJdLCJjb250cm9scyI6WyJhcHBfcmVzIl0sImNvbnRyb2xzX2F1ZHMiOlsiNWUzY2U2YzAtMmIxZi00Mjg1LThkNGItNzVlZTc4Nzg3MzQ2IiwiY2MxNWZkNTctMmM2Yy00MTE3LWE4OGMtODNiMWQ1NmI0YmJlIl0sImRldmljZWlkIjoiM2NiYjEyZGEtZDEzNi00MzExLWFiNTEtYTVjYjQ2OWVmMzk2IiwiZmFtaWx5X25hbWUiOiJIcnVza2EiLCJnaXZlbl9uYW1lIjoiSmlyaSIsImlwYWRkciI6Ijk0LjIzMC4xNTMuMjI0IiwibmFtZSI6IkppcmkgSHJ1c2thIiwib2lkIjoiZjFlODNkN2ItZmExZC00YzM0LWEzZmMtYzUyNjI3ODg1ZThhIiwib25wcmVtX3NpZCI6IlMtMS01LTIxLTE3MjEyNTQ3NjMtNDYyNjk1ODA2LTE1Mzg4ODIyODEtMzQ4NzYzOCIsInB1aWQiOiIxMDAzQkZGRDg2QjUxODBCIiwicmgiOiIwLkFSb0F2NGo1Y3ZHR3IwR1JxeTE4MEJIYlIxZjlGY3hzTEJkQnFJeURzZFZyUzc0YUFGdy4iLCJzY3AiOiJ1c2VyX2ltcGVyc29uYXRpb24iLCJzaWQiOiIyMGE3NjQ3Mi0xMTA4LTQ5NGYtODEyMy0wMWJjMWQ3ZjRkOTMiLCJzaWduaW5fc3RhdGUiOlsiZHZjX21uZ2QiLCJkdmNfY21wIiwia21zaSJdLCJzdWIiOiJfcXpVOXZIcXFRWGdlSDRHLTdyR3NVdWZYci1XNjNfSS1VWTJnSXg3X3hrIiwidGlkIjoiNzJmOTg4YmYtODZmMS00MWFmLTkxYWItMmQ3Y2QwMTFkYjQ3IiwidW5pcXVlX25hbWUiOiJqaWhydXNrYUBtaWNyb3NvZnQuY29tIiwidXBuIjoiamlocnVza2FAbWljcm9zb2Z0LmNvbSIsInV0aSI6ImF6OEs1TkVtUmsyRFl1U3FFdU5yQUEiLCJ2ZXIiOiIxLjAiLCJ3aWRzIjpbImI3OWZiZjRkLTNlZjktNDY4OS04MTQzLTc2YjE5NGU4NTUwOSJdLCJ4bXNfY2MiOlsiQ1AxIl0sInhtc19zc20iOiIxIn0.e8ls6Q33KH1_idxYTRIu8uva6SuEFiTXTP-VRrJTIs6G0Zpwft_0AuFu_wAdT3FRv3UXZpt3lKCBt4TlBSGLrVHsZ1VpMAZh7zOgiGm8MbwB4EUXZtyDgR5XGVhHQIewqYeGsnsrF7ckV5YVC7F4yWaBTK8H-Dga6_7XAYJFsV9MPpCjC1SXb1h70ngjYW1YaGmxQ8wXtYvIwTgHFp674RrAHBD8e_Cch-8lm1H5JqDCIVGYYi_f09M3KQO0oTH36g4uM4X8A6HTaxIsfp4WaEzmIWvIUwKaQIXQk2qgghh5DJ7ETM_A9CLzOYZ4CX72p61w8MIKQRmcwjFDUSNKUw";

        // PFT
        {
            var parts = token.Split('.');
            var header = JsonSerializer.Deserialize<Dictionary<string, object>>(Base64UrlEncoder.Decode(parts[0]));
            if (header != null && header.TryGetValue("nonce", out var nonce) && nonce != null)
            {
                using var hasher = SHA256.Create();
                var hashedNonce = Base64UrlEncoder.Encode(hasher.ComputeHash(Encoding.UTF8.GetBytes(nonce.ToString() ?? "")));
                header["nonce"] = hashedNonce;
                token = Base64UrlEncoder.Encode(JsonSerializer.Serialize(header)) + "." + parts[1] + "." + parts[2];
            }
        }

        return token;
    }

    [Benchmark]
    public bool RS256_Default()
    {
        return _jwtHandler.ValidateToken(_token, _tvpDefault).IsValid;
    }

    [Benchmark]
    public bool RS256_CSP()
    {
        return _jwtHandler.ValidateToken(_token, _tvpCsp).IsValid;
    }
}
#endif
