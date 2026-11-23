# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.CIMD.ReqFetcherConnectionTest do
  @moduledoc """
  The default fetcher's connection, against a real socket. `fetch/2` only
  speaks HTTPS, so these tests drive its request step (`ReqFetcher.get/4`)
  over plain HTTP to a local server: what they check (connection resources
  and the total deadline) does not depend on TLS.
  """
  use ExUnit.Case, async: false

  alias AshAuthentication.Oauth2Server.CIMD.ReqFetcher

  @body ~s({"client_id": "x"})

  # A one-connection-at-a-time HTTP/1.1 server. `respond` gets the socket
  # once the request head is read; the test process is told each Host header.
  defp start_server(respond) do
    {:ok, listen} =
      :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false, reuseaddr: true])

    {:ok, port} = :inet.port(listen)
    test = self()
    server = spawn_link(fn -> accept_loop(listen, respond, test) end)
    on_exit(fn -> Process.exit(server, :kill) end)
    port
  end

  defp accept_loop(listen, respond, test) do
    {:ok, socket} = :gen_tcp.accept(listen)
    {:ok, head} = read_head(socket, "")
    [_, host] = Regex.run(~r/\r\nhost: ([^\r]+)\r\n/i, head)
    send(test, {:host, host})
    respond.(socket)
    :gen_tcp.close(socket)
    accept_loop(listen, respond, test)
  end

  defp read_head(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      {:ok, acc}
    else
      with {:ok, data} <- :gen_tcp.recv(socket, 0, 5_000), do: read_head(socket, acc <> data)
    end
  end

  defp ok(socket) do
    :gen_tcp.send(
      socket,
      "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n" <>
        "content-length: #{byte_size(@body)}\r\nconnection: close\r\n\r\n" <> @body
    )
  end

  defp get(port, hostname, opts \\ []) do
    ReqFetcher.get(
      "http://127.0.0.1:#{port}/oauth/client-metadata.json",
      hostname,
      ReqFetcher.deadline(opts),
      opts
    )
  end

  defp finch_pools, do: DynamicSupervisor.count_children(Req.FinchSupervisor).active

  test "a fetch reaches the pinned address with the original hostname" do
    port = start_server(&ok/1)

    assert {:ok, %{document: %{"client_id" => "x"}}} = get(port, "client.example.net")
    assert_receive {:host, "client.example.net:" <> _}
  end

  test "new hostnames start no connection pool and create no atoms" do
    port = start_server(&ok/1)

    # The first fetch loads code; count only after it.
    assert {:ok, _} = get(port, "warm-up.example.net")
    pools = finch_pools()
    atoms = :erlang.system_info(:atom_count)

    for n <- 1..3 do
      host = "h#{System.unique_integer([:positive])}-#{n}.attacker.example"
      assert {:ok, _} = get(port, host)
    end

    assert finch_pools() == pools
    assert :erlang.system_info(:atom_count) == atoms
  end
end
