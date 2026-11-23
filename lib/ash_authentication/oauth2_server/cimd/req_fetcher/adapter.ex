# SPDX-FileCopyrightText: 2026 ash_authentication_oauth2_server contributors <https://github.com/ash-project/ash_authentication_oauth2_server/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.CIMD.ReqFetcher.Adapter do
  @moduledoc false
  # The `Req` adapter behind `ReqFetcher`: one Mint connection per request,
  # closed once the response is read.
  #
  # Req's default adapter starts a Finch pool, with a new atom for its name,
  # for every distinct `connect_options`. The pinned connect has to put the
  # document's hostname there, so each new hostname left a pool and an atom
  # behind for the life of the node. A connection here lives only as long as
  # its request, and nothing is named after the host.
  #
  # Reads `:hostname` (TLS verification, SNI and the Host header),
  # `:connect_timeout` and `:receive_timeout` (ms), and `:deadline` (the
  # monotonic ms by which the whole response must be read) from the
  # request's `:cimd_fetch` private field. The URL's host is the validated IP
  # literal.

  @private :cimd_fetch

  def run(request) do
    %{hostname: hostname} = settings = Req.Request.get_private(request, @private)
    url = request.url
    {:ok, ip} = url.host |> String.to_charlist() |> :inet.parse_address()

    with {:ok, timeout} <- timeout(settings.connect_timeout, settings.deadline),
         connect_opts = [
           hostname: hostname,
           mode: :passive,
           protocols: [:http1],
           transport_opts: [timeout: timeout]
         ],
         {:ok, conn} <- Mint.HTTP.connect(scheme(url), ip, url.port, connect_opts) do
      {conn, result} = send_and_receive(conn, request, settings)
      Mint.HTTP.close(conn)
      {request, result}
    else
      {:error, error} -> {request, exception(error)}
    end
  end

  # A step's timeout, cut to what is left before the deadline.
  defp timeout(step_timeout, deadline) do
    case deadline - System.monotonic_time(:millisecond) do
      left when left > 0 -> {:ok, min(step_timeout, left)}
      _ -> {:error, %Req.TransportError{reason: :timeout}}
    end
  end

  defp scheme(%URI{scheme: "https"}), do: :https
  defp scheme(%URI{scheme: "http"}), do: :http

  defp send_and_receive(conn, request, settings) do
    path =
      (request.url.path || "/") <> if(request.url.query, do: "?" <> request.url.query, else: "")

    headers = for {name, values} <- request.headers, value <- values, do: {name, value}

    case Mint.HTTP.request(conn, "GET", path, headers, nil) do
      {:ok, conn, ref} ->
        receive_response(conn, ref, {request, Req.Response.new()}, settings)

      {:error, conn, error} ->
        {conn, exception(error)}
    end
  end

  defp receive_response(conn, ref, acc, settings) do
    with {:ok, timeout} <- timeout(settings.receive_timeout, settings.deadline),
         {:ok, conn, responses} <- Mint.HTTP.recv(conn, 0, timeout) do
      case handle(responses, ref, acc) do
        {:cont, acc} -> receive_response(conn, ref, acc, settings)
        {:done, {_request, response}} -> {conn, response}
      end
    else
      {:error, error} -> {conn, error}
      {:error, conn, error, _responses} -> {conn, exception(error)}
    end
  end

  defp handle([], _ref, acc), do: {:cont, acc}

  defp handle([{:status, ref, status} | rest], ref, {request, response}),
    do: handle(rest, ref, {request, %{response | status: status}})

  defp handle([{:headers, ref, headers} | rest], ref, {request, response}) do
    response = %{
      Req.Response.new(status: response.status, headers: headers)
      | private: response.private
    }

    handle(rest, ref, {request, response})
  end

  # The body goes through the request's `into` function, as with Req's own
  # adapter; `:halt` (the size cap) ends the response early.
  defp handle([{:data, ref, data} | rest], ref, acc) do
    case acc |> elem(0) |> Map.fetch!(:into) |> apply([{:data, data}, acc]) do
      {:cont, acc} -> handle(rest, ref, acc)
      {:halt, acc} -> {:done, acc}
    end
  end

  defp handle([{:done, ref} | _rest], ref, acc), do: {:done, acc}
  defp handle([_other | rest], ref, acc), do: handle(rest, ref, acc)

  defp exception(%Req.TransportError{} = error), do: error
  defp exception(%Mint.TransportError{reason: reason}), do: %Req.TransportError{reason: reason}

  defp exception(%Mint.HTTPError{reason: reason}),
    do: %Req.HTTPError{protocol: :http1, reason: reason}
end
