# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.CustomClaimsTest do
  @moduledoc """
  `:access_token_claims` adds application claims to the access tokens of
  both grants, from the grant record, and cannot override the server's own.
  """
  use ExUnit.Case, async: false

  alias AshAuthentication.Oauth2Server
  alias AshAuthentication.Oauth2Server.{Authorize, Jwt, PKCE, Register, Token}
  alias Oauth2ServerTest.ClaimsServer, as: Server

  alias Oauth2ServerTest.{
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthConsent,
    OAuthRefreshToken,
    User
  }

  @redirect_uri "https://chat.example.com/cb"
  @resource "https://app.example.com/mcp"

  setup do
    for resource <- [OAuthClient, OAuthAuthorizationCode, OAuthRefreshToken, OAuthConsent, User] do
      Ash.bulk_destroy!(resource, :destroy, %{}, return_errors?: true)
    end

    user =
      User
      |> Ash.Changeset.for_create(:create, %{email: "alice@example.com"})
      |> Ash.create!()

    {:ok, client, _body} =
      Register.register(Server, %{
        "client_name" => "Test",
        "redirect_uris" => [@redirect_uri],
        "grant_types" => ["authorization_code", "refresh_token"]
      })

    verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    {:ok, validated} =
      Authorize.validate_request(Server, %{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => @redirect_uri,
        "code_challenge" => PKCE.challenge(verifier),
        "code_challenge_method" => "S256",
        "scope" => "mcp"
      })

    code = Authorize.issue_code!(Server, user, validated)

    {:ok, tokens} =
      Token.exchange_authorization_code(Server, %{
        "grant_type" => "authorization_code",
        "code" => code.id,
        "redirect_uri" => @redirect_uri,
        "code_verifier" => verifier,
        "client_id" => client.id
      })

    {:ok, user: user, client: client, tokens: tokens}
  end

  test "an authorization code grant carries the claims built from the code", ctx do
    assert {:ok, claims} = Jwt.verify(Server, ctx.tokens.access_token)

    assert %{
             "app_grant" => "OAuthAuthorizationCode",
             "app_user_id" => user_id,
             "app_scope" => "mcp",
             "app_resource" => @resource
           } = claims

    assert user_id == ctx.user.id
  end

  test "a refresh grant carries the claims built from the refresh token", ctx do
    assert {:ok, %{access_token: access}} =
             Token.exchange_refresh_token(Server, %{
               "grant_type" => "refresh_token",
               "refresh_token" => ctx.tokens.refresh_token,
               "client_id" => ctx.client.id
             })

    assert {:ok, %{"app_grant" => "OAuthRefreshToken"}} = Jwt.verify(Server, access)
  end

  test "the hook cannot override the server's claims or add a tenant", ctx do
    assert {:ok, claims} = Jwt.verify(Server, ctx.tokens.access_token)
    assert claims["sub"] == ctx.user.id
    refute Map.has_key?(claims, "tenant")
  end

  test "a server without the option adds no claims" do
    assert Oauth2Server.__resolve_claims__!(nil, %{}) == %{}
    assert Oauth2Server.__resolve_claims__!(fn _ -> %{"a" => 1} end, %{}) == %{"a" => 1}

    assert_raise RuntimeError, ~r/expected a map of claims/, fn ->
      Oauth2Server.__resolve_claims__!(fn _ -> :nope end, %{})
    end
  end
end
