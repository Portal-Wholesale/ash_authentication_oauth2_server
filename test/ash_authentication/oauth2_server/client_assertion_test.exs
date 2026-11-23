# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ClientAssertionTest do
  @moduledoc """
  `private_key_jwt` for Client ID Metadata Document clients: the assertion
  checks of `AshAuthentication.Oauth2Server.ClientAssertion`, key selection,
  `jti` replay, and how the token endpoint reports each failure. Documents
  and key sets come from `Oauth2ServerTest.StubFetcher`.
  """
  use ExUnit.Case, async: false

  alias AshAuthentication.Oauth2Server.{Authorize, CIMD, ClientAssertion, PKCE, Token}
  alias AshAuthentication.Phoenix.Oauth2Server.Errors

  alias Oauth2ServerTest.{
    FailingClientAssertion,
    FailingJtiServer,
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthClientAssertion,
    OAuthConsent,
    OAuthRefreshToken,
    PrivateKeyJwtServer,
    StubFetcher,
    User
  }

  @client_id "https://app.example.net/oauth/client-metadata.json"
  @jwks_uri "https://app.example.net/oauth/jwks.json"
  @redirect_uri "https://app.example.net/callback"
  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  @issuer "https://app.example.com"
  @token_endpoint @issuer <> "/oauth/token"

  setup do
    for resource <- [
          OAuthClient,
          OAuthAuthorizationCode,
          OAuthRefreshToken,
          OAuthConsent,
          OAuthClientAssertion,
          FailingClientAssertion,
          User
        ] do
      Ash.bulk_destroy!(resource, :destroy, %{}, return_errors?: true)
    end

    StubFetcher.clear()
    on_exit(&StubFetcher.clear/0)

    ec = JOSE.JWK.generate_key({:ec, "P-256"})
    {:ok, ec: ec}
  end

  defp public_jwk(jwk, kid) do
    {_, map} = jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
    if kid, do: Map.put(map, "kid", kid), else: map
  end

  defp document(overrides) do
    Map.merge(
      %{
        "client_id" => @client_id,
        "client_name" => "Assertion Test Client",
        "redirect_uris" => [@redirect_uri],
        "grant_types" => ["authorization_code", "refresh_token"],
        "response_types" => ["code"],
        "token_endpoint_auth_method" => "private_key_jwt"
      },
      overrides
    )
  end

  defp register(server \\ PrivateKeyJwtServer, overrides) do
    StubFetcher.stub(@client_id, document(overrides))
    {:ok, client} = CIMD.resolve_client(server, @client_id)
    client
  end

  defp claims(overrides \\ %{}) do
    now = System.system_time(:second)

    Map.merge(
      %{
        "iss" => @client_id,
        "sub" => @client_id,
        "aud" => @token_endpoint,
        "exp" => now + 60,
        "iat" => now,
        "jti" => Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)
      },
      overrides
    )
  end

  defp sign(jwk, header, claims) do
    {_, token} = jwk |> JOSE.JWT.sign(header, claims) |> JOSE.JWS.compact()
    token
  end

  defp authenticate(server \\ PrivateKeyJwtServer, client, assertion) do
    ClientAssertion.authenticate(
      server,
      client,
      @client_id,
      %{"client_assertion_type" => @assertion_type, "client_assertion" => assertion},
      []
    )
  end

  describe "assertion claims" do
    setup %{ec: ec} do
      {:ok, client: register(%{"jwks" => %{"keys" => [public_jwk(ec, "k1")]}})}
    end

    test "a well-formed assertion is accepted", %{ec: ec, client: client} do
      assert :ok = authenticate(client, sign(ec, %{"alg" => "ES256", "kid" => "k1"}, claims()))
    end

    test "an expired exp, an exp over 1 h ahead, iss ≠ sub, and a future nbf or iat are refused",
         %{ec: ec, client: client} do
      now = System.system_time(:second)

      for {label, overrides} <- [
            expired: %{"exp" => now - 60},
            too_far: %{"exp" => now + 60 * 60 + 120},
            iss_not_sub: %{"sub" => "https://other.example.net/client.json"},
            future_nbf: %{"nbf" => now + 120},
            future_iat: %{"iat" => now + 120}
          ] do
        assertion = sign(ec, %{"alg" => "ES256", "kid" => "k1"}, claims(overrides))

        assert {:error, :invalid_client_assertion} = authenticate(client, assertion),
               "expected #{label} to be refused"
      end
    end

    test "alg none is refused", %{client: client} do
      encode = &Base.url_encode64(Jason.encode!(&1), padding: false)
      unsigned = encode.(%{"alg" => "none", "kid" => "k1"}) <> "." <> encode.(claims()) <> "."

      assert {:error, :invalid_client_assertion} = authenticate(client, unsigned)
    end

    test "a list aud is accepted when it names the token endpoint, refused otherwise",
         %{ec: ec, client: client} do
      header = %{"alg" => "ES256", "kid" => "k1"}
      named = claims(%{"aud" => ["https://elsewhere.example", @token_endpoint]})
      unnamed = claims(%{"aud" => ["https://elsewhere.example", @issuer <> "/other"]})

      assert :ok = authenticate(client, sign(ec, header, named))
      assert {:error, :invalid_client_assertion} = authenticate(client, sign(ec, header, unnamed))
    end
  end

  describe "algorithm" do
    test "an algorithm other than the document's is refused", %{ec: ec} do
      rsa = JOSE.JWK.generate_key({:rsa, 2048})

      client =
        register(%{
          "token_endpoint_auth_signing_alg" => "ES256",
          "jwks" => %{"keys" => [public_jwk(ec, "ec"), public_jwk(rsa, "rsa")]}
        })

      assert :ok = authenticate(client, sign(ec, %{"alg" => "ES256", "kid" => "ec"}, claims()))

      assert {:error, :invalid_client_assertion} =
               authenticate(client, sign(rsa, %{"alg" => "RS256", "kid" => "rsa"}, claims()))
    end
  end

  describe "key selection" do
    setup %{ec: ec} do
      other = JOSE.JWK.generate_key({:ec, "P-256"})

      # Keys from jwks_uri, fetched through the server's fetcher.
      StubFetcher.stub(@jwks_uri, %{"keys" => [public_jwk(other, "k0"), public_jwk(ec, "k1")]})
      {:ok, client: register(%{"jwks_uri" => @jwks_uri}), other: other}
    end

    test "a multi-key set selects by kid", %{ec: ec, other: other, client: client} do
      assert :ok = authenticate(client, sign(ec, %{"alg" => "ES256", "kid" => "k1"}, claims()))
      assert :ok = authenticate(client, sign(other, %{"alg" => "ES256", "kid" => "k0"}, claims()))

      # The kid picks the key, so a signature by the other key fails.
      assert {:error, :invalid_client_assertion} =
               authenticate(client, sign(other, %{"alg" => "ES256", "kid" => "k1"}, claims()))
    end

    test "a multi-key set with no kid in the header is refused", %{ec: ec, client: client} do
      assert {:error, :invalid_client_assertion} =
               authenticate(client, sign(ec, %{"alg" => "ES256"}, claims()))
    end
  end

  describe "jti replay" do
    setup %{ec: ec} do
      {:ok, client: register(%{"jwks" => %{"keys" => [public_jwk(ec, "k1")]}})}
    end

    test "reusing an assertion unchanged is refused; only a new jti is accepted",
         %{ec: ec, client: client} do
      header = %{"alg" => "ES256", "kid" => "k1"}
      first = claims()
      assertion = sign(ec, header, first)

      assert :ok = authenticate(client, assertion)
      assert {:error, :invalid_client_assertion} = authenticate(client, assertion)

      # Re-signed with the same jti but a new exp and iat: still a replay.
      later = %{first | "exp" => first["exp"] + 30, "iat" => first["iat"] + 1}

      assert {:error, :invalid_client_assertion} =
               authenticate(client, sign(ec, header, later))

      # The same claims with a new jti pass, so the refusal is the jti's.
      assert :ok = authenticate(client, sign(ec, header, %{first | "jti" => "fresh"}))
    end

    test "a store error while recording the jti is a server error", %{ec: ec} do
      client =
        register(FailingJtiServer, %{"jwks" => %{"keys" => [public_jwk(ec, "k1")]}})

      assertion = sign(ec, %{"alg" => "ES256", "kid" => "k1"}, claims())

      assert {:error, :server_error} = authenticate(FailingJtiServer, client, assertion)
    end
  end

  describe "token endpoint" do
    setup %{ec: ec} do
      user =
        User
        |> Ash.Changeset.for_create(:create, %{email: "alice@example.com"})
        |> Ash.create!()

      {:ok, user: user, keys: %{"jwks" => %{"keys" => [public_jwk(ec, "k1")]}}}
    end

    defp exchange(server, user, assertion) do
      verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

      {:ok, validated} =
        Authorize.validate_request(server, %{
          "response_type" => "code",
          "client_id" => @client_id,
          "redirect_uri" => @redirect_uri,
          "code_challenge" => PKCE.challenge(verifier),
          "code_challenge_method" => "S256",
          "scope" => "mcp",
          "state" => "csrf-state",
          "resource" => server.resource_url()
        })

      code = Authorize.issue_code!(server, user, validated)

      Token.exchange_authorization_code(server, %{
        "grant_type" => "authorization_code",
        "code" => code.id,
        "redirect_uri" => @redirect_uri,
        "code_verifier" => verifier,
        "client_assertion_type" => @assertion_type,
        "client_assertion" => assertion
      })
    end

    test "a replayed assertion is invalid_client", %{ec: ec, user: user, keys: keys} do
      register(keys)
      assertion = sign(ec, %{"alg" => "ES256", "kid" => "k1"}, claims())

      assert {:ok, %{access_token: _}} = exchange(PrivateKeyJwtServer, user, assertion)
      assert {:error, reason} = exchange(PrivateKeyJwtServer, user, assertion)
      assert {401, "invalid_client", _} = Errors.describe_token_error(reason)
    end

    test "a jti store error is server_error", %{ec: ec, user: user, keys: keys} do
      register(FailingJtiServer, keys)
      assertion = sign(ec, %{"alg" => "ES256", "kid" => "k1"}, claims())

      assert {:error, reason} = exchange(FailingJtiServer, user, assertion)
      assert {500, "server_error", _} = Errors.describe_token_error(reason)
    end
  end
end
