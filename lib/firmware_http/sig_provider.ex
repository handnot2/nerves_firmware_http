defmodule Nerves.Firmware.HTTP.SigProvider do
  @behaviour Sigaws.Provider
  import Sigaws.Util, only: [check_expiration: 1, parse_amz_dt: 1, signing_key: 4]
  alias Sigaws.Ctxt
  require Logger

  @region "nerves"
  @service "fw-update"

  def pre_verification(%Ctxt{region: @region, service: @service} = ctxt) do
    check_expiration(ctxt)
  end
  def pre_verification(%Ctxt{region: rg, service: sv}) do
    {:error, :invalid_data, rg <> "/" <> sv}
  end

  def signing_key(%Ctxt{access_key: "admin", signed_at_amz_dt: amz_dt}) do
    secret = Application.get_env(:nerves_firmware_http, :secret)
    case parse_amz_dt(amz_dt) do
      {:ok, dt} -> signing_key(DateTime.to_date(dt), @region, @service, secret)
      error -> error
    end
  end
  def signing_key(_), do: {:error, :unknown, "access_key"}
end

