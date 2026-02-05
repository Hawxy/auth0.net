namespace Auth0.ManagementApi;

public interface ITokenProvider
{
    public ValueTask<string> GetTokenAsync();
}