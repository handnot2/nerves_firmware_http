defmodule Nerves.Firmware.HTTP.Transport do

  @moduledoc false

  @max_upload_chunk 100000        # 100K max chunks to keep memory reasonable
  @max_upload_size  100000000     # 100M max file to avoid using all of flash

  require Logger

  def init(_transport, _req, _state) do
    {:upgrade, :protocol, :cowboy_rest}
  end

  def rest_init(req, handler_opts) do
    {:ok, req, handler_opts}
  end

  def allowed_methods(req, state) do
    {["GET", "PUT", "POST"], req, state}
  end

  def content_types_provided(req, state) do
    {[ {"application/json", :json_provider} ], req, state}
  end

  def content_types_accepted(req, state) do
    {[ {{"application", "x-firmware", []}, :upload_acceptor} ], req, state}
  end

  def json_provider(req, state) do
    {:ok, body} =
      Nerves.Firmware.state
      |> JSX.encode(space: 1, indent: 2)
    { body <> "\n", req, state}
  end

  @doc """
  Acceptor for cowboy to update firmware via HTTP.

  Once firmware is streamed, it returns success (2XX) or failure (4XX/5XX).
  Calls `update_status()` to reflect status at `/sys/firmware`.
  Won't let you upload firmware on top of provisional (returns 403)
  """
  def upload_acceptor(req, state) do
		Logger.info "request to receive firmware"
    if Nerves.Firmware.allow_upgrade? do
      upload_and_apply_firmware_upgrade(req, state)
    else
      {:halt, reply_with(403, req), state}
		end
  end

  # TODO:  Ideally we'd like to allow streaming directly to fwup, but its hard
  # due to limitations with ports and writing to fifo's from elixir
  # Right solution would be to get Porcelain fixed to avoid golang for goon.
  defp upload_and_apply_firmware_upgrade(req, state) do
    stage_file  = Application.get_env(:nerves_firmware_http, :stage_file,
                                      "/tmp/uploaded.fw")
    Logger.info "receiving firmware"
    resp = File.open!(stage_file, [:write], &(stream_fw &1, req))
    Logger.info "firmware received"

    with {:done, req, content_hash} <- resp,
         {:ok, req} <- verify_signature(req, content_hash)
    do
      resp =
        stage_file
        |> Nerves.Firmware.upgrade_and_finalize()
        |> process_upgrade_result(req, state)
      File.rm stage_file
      resp
    else
      {:error, :verification_failed, req} ->
        File.rm stage_file
        {:halt, reply_with(401, req), state}
      error ->
        Logger.error(IO.inspect(error))
        File.rm stage_file
        {:halt, reply_with(400, req), state}
    end
  end

  defp process_upgrade_result(:ok, req, state) do
    if reboot?(:cowboy_req.header("x-reboot", req)) do
      reply_with(200, req)
      Nerves.Firmware.reboot()
    end
    {true, req, state}
  end
  defp process_upgrade_result({:error, _}, req, state) do
    {:halt, reply_with(400, req), state}
  end

  defp reboot?({:undefined, _}), do: false
  defp reboot?({_, _}), do: true

  # helper to return errors to requests from cowboy more easily
  defp reply_with(code, req) do
    {:ok, req} = :cowboy_req.reply(code, [], req)
    req
  end

  # copy from a cowboy req into a IO.Stream
  defp stream_fw(f, req), do: stream_fw(f, req, 0, :crypto.hash_init(:sha256))
  defp stream_fw(_f, _req, count, _hctxt) when count > @max_upload_size do
    {:error, :too_large}
  end
  defp stream_fw(f, req, count, hctxt) do
    #  send an event about (bytes_uploaded: count)
    case :cowboy_req.body(req, length: @max_upload_chunk) do
      {:more, chunk, new_req} ->
        :ok = IO.binwrite f, chunk
        hctxt = :crypto.hash_update(hctxt, chunk)
        stream_fw(f, new_req, (count + byte_size(chunk)), hctxt)
      {:ok, chunk, new_req} ->
        :ok = IO.binwrite f, chunk
        content_hash =
          hctxt
          |> :crypto.hash_update(chunk)
          |> :crypto.hash_final()
          |> Base.encode16(case: :lower)
        {:done, new_req, content_hash}
    end
  end

  defp verify_signature(req, content_hash) do
    protected? = Application.get_env(:nerves_firmware_http, :secret) != nil
    if protected? do
      {rp, req} = :cowboy_req.path(req)
      {md, req} = :cowboy_req.method(req)
      {qs, req} = :cowboy_req.qs(req)
      {hd, req} = :cowboy_req.headers(req)

      result = Sigaws.verify(rp, method: md, query_string: qs, headers: hd,
                             body: {:content_hash, content_hash},
                             provider: Nerves.Firmware.HTTP.SigProvider)
      case result do
        {:ok, _} ->
          Logger.info "sigaws result = #{inspect result}"
          {:ok, req}
        {:error, _, _} ->
          Logger.error "sigaws result = #{inspect result}"
          {:error, :verification_failed, req}
      end
    else
      {:ok, req}
    end
  end
end
