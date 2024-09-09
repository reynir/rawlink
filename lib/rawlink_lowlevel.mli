type driver = AF_PACKET | BPF
external opensock :
  ?filter:string -> ?promisc:bool -> string -> Unix.file_descr
  = "caml_rawlink_open"
external dhcp_server_filter : unit -> string = "caml_dhcp_server_filter"
external dhcp_client_filter : unit -> string = "caml_dhcp_client_filter"
external driver : unit -> driver = "caml_driver"
external unix_bytes_read :
  Unix.file_descr -> Cstruct.buffer -> int -> int -> int
  = "caml_unix_bytes_read"
external bpf_align : int -> int -> int = "caml_bpf_align"
val bpf_split_buffer : Cstruct.t -> int -> Cstruct.t list
val process_input : Cstruct.t -> int -> Cstruct.t list
