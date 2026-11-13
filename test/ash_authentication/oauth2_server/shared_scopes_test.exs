# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.SharedScopesTest do
  @moduledoc """
  `consent_per_resource?: true`: `/mcp` and `/gql` share `openid` and
  `offline_access`, and consent to one resource never covers the other.
  """
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn

  alias AshAuthentication.Oauth2Server
  alias AshAuthentication.Oauth2Server.{Authorize, PKCE, Register}
  alias AshAuthentication.Phoenix.Oauth2Server.ConsentRouter
  alias Oauth2ServerTest.SharedScopeServer, as: Server

  alias Oauth2ServerTest.{
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthRefreshToken,
    OAuthResourceConsent,
    User
  }

  @mcp "https://app.example.com/mcp"
  @gql "https://app.example.com/gql"
  @redirect_uri "https://chat.example.com/cb"

  setup do
    for resource <- [
          OAuthClient,
          OAuthAuthorizationCode,
          OAuthRefreshToken,
          OAuthResourceConsent,
          User
        ] do
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

    {:ok, user: user, client: client}
  end

  defp authorize_params(client, overrides) do
    verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

    Map.merge(
      %{
        "response_type" => "code",
        "client_id" => client.id,
        "redirect_uri" => @redirect_uri,
        "code_challenge" => PKCE.challenge(verifier),
        "code_challenge_method" => "S256",
        "scope" => "openid offline_access mcp"
      },
      overrides
    )
  end

  describe "configuration" do
    test "accepts shared scopes only with consent_per_resource?" do
      base = [
        otp_app: :x,
        user_resource: X,
        issuer_url: "i",
        signing_secret: "s",
        client_resource: X,
        authorization_code_resource: X,
        refresh_token_resource: X,
        consent_resource: X,
        scopes: ["a", "b"],
        resources: [m: [url: "r", scopes: ["a"]], g: [url: "q", scopes: ["a", "b"]]]
      ]

      assert :ok = Oauth2Server.__validate_opts__!(M, base ++ [consent_per_resource?: true])
      assert_raise CompileError, fn -> Oauth2Server.__validate_opts__!(M, base) end
    end

    test "requires a consent resource that stores the resource" do
      defmodule NoResourceConsentServer do
        def consent_per_resource?, do: true
        def consent_resource, do: Oauth2ServerTest.OAuthConsent
      end

      assert_raise CompileError, ~r/has no `:resource_uri` attribute/, fn ->
        Oauth2Server.__verify_consent_per_resource__!(NoResourceConsentServer)
      end

      assert :ok = Oauth2Server.__verify_consent_per_resource__!(Server)
    end
  end

  describe "authorize" do
    test "a resource-specific scope selects its resource", %{client: client} do
      assert {:ok, %{resource: @mcp}} =
               Authorize.validate_request(Server, authorize_params(client, %{}))
    end

    test "shared scopes alone need the resource parameter", %{client: client} do
      params = authorize_params(client, %{"scope" => "openid offline_access"})

      assert {:error, "invalid_target", _} = Authorize.validate_request(Server, params)

      assert {:ok, %{resource: @gql}} =
               Authorize.validate_request(Server, Map.put(params, "resource", @gql))
    end
  end

  describe "consent" do
    test "consent to shared scopes at one resource does not cover the other",
         %{user: user, client: client} do
      Authorize.grant_consent!(Server, user, client, "openid offline_access mcp", resource: @mcp)

      assert Authorize.consented?(Server, user, client, "openid offline_access", resource: @mcp)
      refute Authorize.consented?(Server, user, client, "openid offline_access", resource: @gql)

      Authorize.grant_consent!(Server, user, client, "openid gql", resource: @gql)

      assert Authorize.consented?(Server, user, client, "openid gql", resource: @gql)
      refute Authorize.consented?(Server, user, client, "offline_access", resource: @gql)
      assert Authorize.consented?(Server, user, client, "offline_access mcp", resource: @mcp)
      assert length(Ash.read!(OAuthResourceConsent)) == 2
    end

    test "reading or writing consent without the resource raises",
         %{user: user, client: client} do
      assert_raise ArgumentError, ~r/:resource option is required/, fn ->
        Authorize.grant_consent!(Server, user, client, "openid")
      end

      assert_raise ArgumentError, ~r/:resource option is required/, fn ->
        Authorize.consented?(Server, user, client, "openid")
      end
    end

    test "the consent screen asks again for a resource the user has not consented to",
         %{user: user, client: client} do
      Authorize.grant_consent!(Server, user, client, "openid offline_access mcp", resource: @mcp)

      authorize = fn params ->
        conn(:get, "/?" <> URI.encode_query(params))
        |> init_test_session(%{})
        |> Ash.PlugHelpers.set_actor(user)
        |> ConsentRouter.call(ConsentRouter.init(oauth2_server: Server))
      end

      mcp = authorize.(authorize_params(client, %{"resource" => @mcp}))
      assert mcp.status == 302
      assert [location] = get_resp_header(mcp, "location")
      assert location =~ "code="

      gql =
        authorize.(
          authorize_params(client, %{"scope" => "openid offline_access", "resource" => @gql})
        )

      assert gql.status == 200
      assert gql.resp_body =~ ~s(name="consent_request")
    end
  end
end
