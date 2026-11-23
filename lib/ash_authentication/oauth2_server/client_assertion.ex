# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.ClientAssertion do
  @moduledoc """
  Client authentication at the token and revocation endpoints.

  Public clients (`token_endpoint_auth_method: "none"`) must send no
  credentials. A Client ID Metadata Document client whose document declares
  `private_key_jwt` must authenticate with a JWT client assertion
  ([RFC 7523 §2.2](https://www.rfc-editor.org/rfc/rfc7523#section-2.2)),
  signed by a key from the document's `jwks` or `jwks_uri`
  (draft-ietf-oauth-client-id-metadata-document §5). The server never applies
  a default method to such a client.

  The assertion is accepted only when:

    * `client_assertion_type` is `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
      and no other credential is present;
    * its `typ`, if present, is `JWT` or `client-authentication+jwt`
      (draft-ietf-oauth-rfc7523bis), so a JWT the client signed as another
      token type is not taken for an assertion;
    * its `alg` is in `#{inspect(~w(RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 EdDSA))}`
      (and equals the document's `token_endpoint_auth_signing_alg` when the
      document names one), so `none` and the HMAC algorithms never verify;
    * the signature verifies with the client's key, chosen by `kid` (a key set
      without `kid` must hold exactly one signing key);
    * `iss` and `sub` are the presented `client_id`, `aud` names the issuer or
      the token endpoint, `exp` is in the future and at most
      `#{60 * 60}` seconds away, and `nbf`/`iat` are not in the future;
    * its `jti` was not seen before for this client. Each `jti` is stored in the
      server's `:client_assertion_resource` until the assertion expires plus the
      clock skew it is accepted with, so a replay on any node fails even after
      expired rows are pruned.

  `jwks_uri` is fetched through the server's `:cimd_fetcher`, so the same
  outbound policy as the metadata document applies (HTTPS only, public
  addresses only, pinned connect, no redirects, size and time caps). Key sets
  are cached like documents. An unknown `kid` refetches the set, which picks up
  a rotated key, but at most once every 60 seconds for each `jwks_uri`, so
  assertions with made-up `kid`s cannot turn the token endpoint into a stream
  of fetches toward the client's key host.
  """

  require Logger

  alias AshAuthentication.Oauth2Server.CIMD.Cache

  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  @algorithms ~w(RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 EdDSA)
  @max_lifetime 60 * 60
  @ash_context %{private: %{ash_authentication?: true}}
  @jwks_cache_ttl 300
  @jwks_refetch_interval 60

  @doc """
  Whether `server` accepts `private_key_jwt` from CIMD clients. Servers that
  predate the option (or hand-written test doubles) answer `false`.
  """
  @spec enabled?(module()) :: boolean()
  def enabled?(server) do
    Code.ensure_loaded(server)
    function_exported?(server, :private_key_jwt_enabled?, 0) and server.private_key_jwt_enabled?()
  end

  @doc "The signing algorithms accepted for client assertions."
  @spec algorithms() :: [String.t()]
  def algorithms, do: @algorithms

  @doc """
  When a request carries a client assertion but no `client_id`, take the
  `client_id` from the assertion's unverified `iss` (RFC 7523 §3 lets the
  client omit it). `authenticate/5` later requires `iss` to equal the
  `client_id` it was resolved by.
  """
  @spec put_client_id(map()) :: map()
  def put_client_id(%{"client_id" => id} = params) when is_binary(id) and id != "", do: params

  def put_client_id(%{"client_assertion" => assertion} = params) when is_binary(assertion) do
    case peek_claims(assertion) do
      {:ok, %{"iss" => iss}} when is_binary(iss) and iss != "" ->
        Map.put(params, "client_id", iss)

      _ ->
        params
    end
  end

  def put_client_id(params), do: params

  @doc """
  Checks that need no client: shared-secret credentials (HTTP Basic or
  `client_secret`) are never accepted here, so they fail before the request is
  validated, as they did before `private_key_jwt`. More than one mechanism is
  `invalid_request`.
  """
  @spec precheck(map(), keyword()) :: :ok | {:error, atom()}
  def precheck(params, opts) do
    shared_secret? =
      Keyword.get(opts, :authorization_scheme) == "basic" or present?(params["client_secret"])

    case {credential_count(params, opts), shared_secret?} do
      {n, _} when n > 1 -> {:error, :invalid_request}
      {1, true} -> {:error, :unsupported_client_authentication}
      _ -> :ok
    end
  end

  @doc """
  Authenticate `client` for a token or revocation request.

  Returns `:ok`, `{:error, :unsupported_client_authentication}` for a public
  client that sent credentials, `{:error, :invalid_request}` for more than one
  credential, `{:error, :invalid_client_assertion}`, or `{:error, :server_error}`
  when the assertion's `jti` could not be recorded.
  """
  @spec authenticate(module(), Ash.Resource.Record.t(), String.t(), map(), keyword()) ::
          :ok | {:error, atom()}
  def authenticate(server, client, presented_client_id, params, opts) do
    case Map.get(client, :token_endpoint_auth_method) do
      "private_key_jwt" ->
        authenticate_assertion(server, client, presented_client_id, params, opts)

      _ ->
        no_credentials(params, opts)
    end
  end

  # OAuth 2.1 §3.2.2: the server MUST authenticate a client that includes
  # client authentication, and a public client has nothing to check them
  # against. More than one mechanism is `invalid_request` (§3.2.4). An empty
  # `client_secret` counts as omitted.
  defp no_credentials(params, opts) do
    case credential_count(params, opts) do
      0 -> :ok
      1 -> {:error, :unsupported_client_authentication}
      _ -> {:error, :invalid_request}
    end
  end

  defp credential_count(params, opts) do
    Enum.count(
      [
        Keyword.get(opts, :authorization_scheme) == "basic",
        present?(params["client_secret"]),
        present?(params["client_assertion"])
      ],
      & &1
    )
  end

  defp authenticate_assertion(server, client, client_id, params, opts) do
    with 1 <- credential_count(params, opts),
         @assertion_type <- params["client_assertion_type"],
         assertion when is_binary(assertion) and assertion != "" <- params["client_assertion"],
         {:ok, header} <- peek_header(assertion),
         :ok <- check_typ(header),
         {:ok, alg} <- check_alg(header, client),
         {:ok, claims} <- verify_signature(server, client, assertion, alg, header),
         :ok <- check_claims(server, claims, client_id, opts) do
      record_jti(server, client, claims, opts)
    else
      0 -> {:error, :invalid_client_assertion}
      n when is_integer(n) -> {:error, :invalid_request}
      _ -> {:error, :invalid_client_assertion}
    end
  end

  # The rfc7523bis value is not required: clients in use today, ChatGPT among
  # them, may send `JWT` or no `typ` at all. Media types are case-insensitive
  # and may carry the `application/` prefix (RFC 7515 §4.1.9).
  defp check_typ(%{"typ" => typ}) when is_binary(typ) do
    case String.downcase(typ) do
      "application/" <> type when type in ["jwt", "client-authentication+jwt"] -> :ok
      type when type in ["jwt", "client-authentication+jwt"] -> :ok
      _ -> {:error, :typ}
    end
  end

  defp check_typ(%{"typ" => _}), do: {:error, :typ}
  defp check_typ(_header), do: :ok

  defp check_alg(%{"alg" => alg}, client) when alg in @algorithms do
    case Map.get(client, :token_endpoint_auth_signing_alg) do
      nil -> {:ok, alg}
      ^alg -> {:ok, alg}
      _ -> {:error, :alg}
    end
  end

  defp check_alg(_, _), do: {:error, :alg}

  defp verify_signature(server, client, assertion, alg, header) do
    with {:ok, keys, source} <- client_keys(server, client, false),
         {:ok, jwk} <- select_key(keys, header, alg, source, server, client) do
      case JOSE.JWT.verify_strict(JOSE.JWK.from_map(jwk), [alg], assertion) do
        {true, %JOSE.JWT{fields: claims}, _jws} -> {:ok, claims}
        _ -> {:error, :signature}
      end
    end
  rescue
    _ -> {:error, :signature}
  end

  # An unknown `kid` in a cached key set refetches the set, at most once per
  # `@jwks_refetch_interval` for the client's `jwks_uri`.
  defp select_key(keys, header, alg, source, server, client) do
    case find_key(keys, header, alg) do
      {:ok, jwk} ->
        {:ok, jwk}

      :error when source == :cached ->
        with true <- refetch_allowed?(client),
             {:ok, fresh, _} <- client_keys(server, client, true),
             {:ok, jwk} <- find_key(fresh, header, alg) do
          {:ok, jwk}
        else
          _ -> {:error, :no_key}
        end

      :error ->
        {:error, :no_key}
    end
  end

  # A key set is only `:cached` when the cache is running, so the mark is kept.
  defp refetch_allowed?(%{jwks_uri: uri}) do
    key = "jwks-refetch:" <> uri

    case Cache.get(key) do
      {:ok, _} ->
        false

      :miss ->
        Cache.put(key, %{}, @jwks_refetch_interval)
        true
    end
  end

  defp find_key(keys, %{"kid" => kid}, alg) when is_binary(kid) do
    case Enum.filter(keys, &(&1["kid"] == kid and signing_key?(&1, alg))) do
      [jwk] -> {:ok, jwk}
      _ -> :error
    end
  end

  defp find_key(keys, _header, alg) do
    case Enum.filter(keys, &signing_key?(&1, alg)) do
      [jwk] -> {:ok, jwk}
      _ -> :error
    end
  end

  defp signing_key?(%{"kty" => kty} = jwk, alg) do
    jwk["use"] in [nil, "sig"] and jwk["alg"] in [nil, alg] and kty_for(alg) == kty and
      not Map.has_key?(jwk, "d")
  end

  defp signing_key?(_, _), do: false

  defp kty_for("RS" <> _), do: "RSA"
  defp kty_for("PS" <> _), do: "RSA"
  defp kty_for("ES" <> _), do: "EC"
  defp kty_for("EdDSA"), do: "OKP"

  # `jwks` inline in the document wins; the CIMD draft forbids both.
  defp client_keys(_server, %{jwks: %{"keys" => keys}}, _refresh?) when is_list(keys),
    do: {:ok, keys, :inline}

  defp client_keys(server, %{jwks_uri: "https://" <> _ = uri}, refresh?) do
    cache_key = "jwks:" <> uri

    case if(refresh?, do: :miss, else: Cache.get(cache_key)) do
      {:ok, %{"keys" => keys}} ->
        {:ok, keys, :cached}

      _ ->
        case server.cimd_fetcher().fetch(uri, server.cimd_fetch_options()) do
          {:ok, %{document: %{"keys" => keys} = jwks}} when is_list(keys) ->
            Cache.put(cache_key, jwks, @jwks_cache_ttl)
            {:ok, keys, :fetched}

          other ->
            Logger.warning(
              "Oauth2Server: failed to fetch client jwks from #{inspect(uri)}: #{inspect(other)}"
            )

            {:error, :jwks}
        end
    end
  end

  defp client_keys(_server, _client, _refresh?), do: {:error, :no_keys}

  defp check_claims(server, claims, client_id, opts) do
    now = System.system_time(:second)
    skew = server.clock_skew_seconds()
    issuer = server.issuer_url(secret_context(opts))

    with ^client_id <- claims["iss"],
         ^client_id <- claims["sub"],
         true <- audience_ok?(claims["aud"], [issuer, issuer <> "/oauth/token"]),
         exp when is_integer(exp) <- claims["exp"],
         true <- exp + skew > now and exp - now <= @max_lifetime,
         true <- not_after?(claims["nbf"], now + skew),
         true <- not_after?(claims["iat"], now + skew),
         jti when is_binary(jti) and jti != "" <- claims["jti"] do
      :ok
    else
      _ -> {:error, :claims}
    end
  end

  defp audience_ok?(aud, accepted) when is_binary(aud), do: aud in accepted
  defp audience_ok?(aud, accepted) when is_list(aud), do: Enum.any?(aud, &(&1 in accepted))
  defp audience_ok?(_, _), do: false

  defp not_after?(nil, _limit), do: true
  defp not_after?(value, limit) when is_integer(value), do: value <= limit
  defp not_after?(_, _), do: false

  # The row outlives the assertion by the clock skew `check_claims/4` allows
  # past `exp`, so pruning expired rows never reopens a `jti` that would still
  # verify.
  defp record_jti(server, client, claims, opts) do
    attrs = %{
      client_id: client.id,
      jti: claims["jti"],
      expires_at: DateTime.from_unix!(claims["exp"] + server.clock_skew_seconds())
    }

    server.client_assertion_resource()
    |> Ash.Changeset.for_create(:record, attrs)
    |> Ash.create(ash_opts(opts))
    |> case do
      {:ok, _} ->
        :ok

      {:error, error} ->
        # Only a replayed `jti`, which hits the unique identity, is the
        # client's fault. Any other failure leaves the assertion unrecorded,
        # so it must not be accepted, and it is not the client's error either.
        if unique_violation?(error) do
          {:error, :invalid_client_assertion}
        else
          Logger.error("Oauth2Server: failed to record client assertion jti: #{inspect(error)}")
          {:error, :server_error}
        end
    end
  end

  # A data layer that enforces the identity reports a unique constraint
  # (AshPostgres); the identity pre-check reports the identity's fields.
  defp unique_violation?(%Ash.Error.Invalid{errors: errors}),
    do: Enum.any?(errors, &unique_violation?/1)

  defp unique_violation?(%Ash.Error.Changes.InvalidAttribute{private_vars: vars}),
    do: is_list(vars) and Keyword.get(vars, :constraint_type) == :unique

  defp unique_violation?(%Ash.Error.Changes.InvalidChanges{fields: fields}),
    do: :jti in List.wrap(fields)

  defp unique_violation?(_), do: false

  defp peek_header(token) do
    with [h, _, _] <- String.split(token, "."),
         {:ok, json} <- Base.url_decode64(h, padding: false),
         {:ok, %{} = header} <- Jason.decode(json) do
      {:ok, header}
    else
      _ -> {:error, :malformed}
    end
  end

  defp peek_claims(token) do
    with [_, c, _] <- String.split(token, "."),
         {:ok, json} <- Base.url_decode64(c, padding: false),
         {:ok, %{} = claims} <- Jason.decode(json) do
      {:ok, claims}
    else
      _ -> {:error, :malformed}
    end
  end

  defp present?(value), do: is_binary(value) and value != ""

  defp secret_context(opts) do
    case Keyword.get(opts, :tenant) do
      nil -> %{}
      tenant -> %{tenant: tenant}
    end
  end

  defp ash_opts(opts) do
    base = [context: @ash_context]

    case Keyword.get(opts, :tenant) do
      nil -> base
      tenant -> Keyword.put(base, :tenant, tenant)
    end
  end
end
