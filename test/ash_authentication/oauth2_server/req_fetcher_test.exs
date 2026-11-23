# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.CIMD.ReqFetcherTest do
  @moduledoc """
  The default fetcher's outbound policy end to end, through `fetch/2`. Req's
  global default options route every request to a plug, so nothing leaves
  the box and each test sees which requests the fetcher made.
  """
  use ExUnit.Case, async: false

  alias AshAuthentication.Oauth2Server.CIMD.ReqFetcher

  # A literal public address needs no DNS and passes the address check.
  @public_url "https://93.184.216.34/oauth/client-metadata.json"

  setup do
    previous = Req.default_options()
    test = self()

    Req.default_options(
      plug: fn conn ->
        send(test, {:requested, conn.request_path})
        Application.fetch_env!(:req, :test_respond).(conn)
      end
    )

    on_exit(fn ->
      Req.default_options(previous)
      Application.delete_env(:req, :test_respond)
    end)

    :ok
  end

  defp respond_with(fun), do: Application.put_env(:req, :test_respond, fun)

  defp json(conn, status, body) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.send_resp(status, body)
  end

  test "a public URL within the policy is fetched" do
    respond_with(&json(&1, 200, ~s({"client_id": "x"})))

    assert {:ok, %{document: %{"client_id" => "x"}}} = ReqFetcher.fetch(@public_url)
    assert_received {:requested, "/oauth/client-metadata.json"}
  end

  test "a host whose DNS answer is a private address is refused before connecting" do
    respond_with(&json(&1, 200, "{}"))

    # `localhost` goes through the resolver, unlike a literal address.
    assert {:error, :non_public_address} =
             ReqFetcher.fetch("https://localhost/oauth/client-metadata.json")

    assert {:error, :non_public_address} =
             ReqFetcher.fetch("https://10.0.0.1/oauth/client-metadata.json")

    refute_received {:requested, _}
  end

  test "a redirect is not followed" do
    respond_with(fn conn ->
      conn
      |> Plug.Conn.put_resp_header("location", "https://93.184.216.34/elsewhere.json")
      |> Plug.Conn.send_resp(302, "")
    end)

    assert {:error, :redirect_not_allowed} = ReqFetcher.fetch(@public_url)
    assert_received {:requested, "/oauth/client-metadata.json"}
    refute_received {:requested, "/elsewhere.json"}
  end

  test "a response over the size cap is refused" do
    padding = String.duplicate("a", 5_120)
    respond_with(&json(&1, 200, ~s({"client_id": "x", "pad": "#{padding}"})))

    assert {:error, :document_too_large} = ReqFetcher.fetch(@public_url)

    # The cap is configurable, and a body under it is read.
    assert {:ok, %{document: %{"client_id" => "x"}}} =
             ReqFetcher.fetch(@public_url, max_body_bytes: 10_000)
  end

  test "2001::/23 (IETF protocol assignments) is refused" do
    for ip <- [
          # 2001::1 (Teredo, 2001::/32)
          {0x2001, 0, 0, 0, 0, 0, 0, 1},
          # 2001:2::1 (benchmarking, 2001:2::/48)
          {0x2001, 0x2, 0, 0, 0, 0, 0, 1},
          # 2001:10::1 (ORCHID, 2001:10::/28)
          {0x2001, 0x10, 0, 0, 0, 0, 0, 1},
          # top of the /23
          {0x2001, 0x1FF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF}
        ] do
      refute ReqFetcher.public_ip?(ip), "expected #{inspect(ip)} to be rejected"
    end

    # 2001:200::/23 is the first block past it (APNIC).
    assert ReqFetcher.public_ip?({0x2001, 0x200, 0, 0, 0, 0, 0, 1})

    respond_with(&json(&1, 200, "{}"))

    assert {:error, :non_public_address} =
             ReqFetcher.fetch("https://[2001::1]/oauth/client-metadata.json")

    refute_received {:requested, _}
  end

  test "a failed DNS lookup is transient unless the name has no address" do
    v4 = {93, 184, 216, 34}
    v6 = {0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25C8, 0x1946}

    assert {:ok, [^v4, ^v6]} = ReqFetcher.dns_result([{:ok, [v4]}, {:ok, [v6]}])
    # An IPv6-only host: IPv4 has no records.
    assert {:ok, [^v6]} = ReqFetcher.dns_result([{:error, :nxdomain}, {:ok, [v6]}])
    assert {:error, :nxdomain} = ReqFetcher.dns_result([{:error, :nxdomain}, {:error, :nxdomain}])

    for reason <- [:timeout, :servfail, :refused, :try_again] do
      assert {:error, %Req.TransportError{reason: ^reason}} =
               ReqFetcher.dns_result([{:error, reason}, {:error, :nxdomain}])

      assert {:error, %Req.TransportError{reason: ^reason}} =
               ReqFetcher.dns_result([{:error, :nxdomain}, {:error, reason}])
    end
  end
end
