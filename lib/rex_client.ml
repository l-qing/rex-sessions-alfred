(* Which Rex app client a client action such as session.select should go to.

   Without -C, rex only picks a client when exactly one app is connected to the server.
   A Rex app on another Mac can connect to this Mac's server too (and this Mac's app to
   theirs), so name this Mac's app explicitly. Its client ID differs on every server it
   connects to, but the label a person gave it is the same everywhere. *)

type app_client = {
  client_id : string;
  label : string;
  transport : string;  (* how it reached the server: "unix" for an app on the same Mac *)
}

(* Yojson's member raises on a non-object, and command-line clients have no "info",
   so read a missing or odd nested object as an empty one. *)
let object_field name (json : Yojson.Safe.t) : Yojson.Safe.t =
  match json with
  | `Assoc fields -> (
      match List.assoc_opt name fields with
      | Some (`Assoc _ as value) -> value
      | _ -> `Assoc [])
  | _ -> `Assoc []

let app_clients_of_json json =
  List.filter_map
    (fun client_json ->
      let info = object_field "info" client_json in
      (* Command-line clients have no info, and helpers report another kind. *)
      if Tab.string_field "kind" info <> "app" then None
      else
        Some
          {
            client_id = Tab.string_field "client_id" client_json;
            label = Tab.string_field "label" info;
            transport =
              Tab.string_field "transport" (object_field "principal" client_json);
          })
    (Tab.list_field "clients" json)

let only_one = function
  | [ single ] -> Some single
  | _ -> None

(* The app on this Mac reaches the local server over its unix socket; apps on other
   machines come in over the network. With two local apps we can't tell which is meant. *)
let local_app_client clients =
  only_one (List.filter (fun client -> client.transport = "unix") clients)

(* An empty or shared label can't identify one app, so it matches nothing. *)
let app_client_with_label label clients =
  if label = "" then None
  else only_one (List.filter (fun client -> client.label = label) clients)

let app_clients_of_host host =
  let result = Rex_cli.run_rex host [ "client"; "ls"; "--json" ] in
  if not (Process.succeeded result) then
    Error (Rex_cli.error_message_of_result result)
  else
    match Yojson.Safe.from_string result.stdout with
    | json -> (
        (* A reply that isn't an object makes member raise; report it like bad JSON. *)
        try Ok (app_clients_of_json json)
        with Yojson.Safe.Util.Type_error (message, _) ->
          Error ("rex client ls printed unexpected JSON: " ^ message))
    | exception Yojson.Json_error message -> Error ("rex client ls printed bad JSON: " ^ message)

(* The client ID of this Mac's Rex app on the host's server, or None (with the reason
   logged) so the caller can fall back to letting rex choose. *)
let client_id_for_host host =
  let found =
    Result.bind (app_clients_of_host Host.Local) (fun local_clients ->
        match local_app_client local_clients with
        | None -> Error "no single Rex app is connected to the local server over unix"
        | Some local_app -> (
            match host with
            | Host.Local -> Ok local_app.client_id
            | Host.Remote host_label ->
                Result.bind (app_clients_of_host host) (fun remote_clients ->
                    match app_client_with_label local_app.label remote_clients with
                    | Some remote_app -> Ok remote_app.client_id
                    | None ->
                        Error
                          (Printf.sprintf "no single app labeled %S is connected to %s"
                             local_app.label host_label))))
  in
  match found with
  | Ok client_id -> Some client_id
  | Error reason ->
      Activity_log.log_line "could not choose a Rex app client for %s: %s"
        (Host.label_of_host host) reason;
      None
