package outputs

var ESmapping = `
{
	"index_patterns": [
	  "${INDEX}${PATTERN}"
	],
	"template": {
	  "settings": {
		"number_of_shards": ${SHARDS},
		"number_of_replicas": ${REPLICAS}
	  },
	  "mappings": {
		"properties": {
		  "@timestamp": {
			"type": "date"
		  },
		  "hostname": {
			"type": "text",
			"fields": {
			  "keyword": {
				"type": "keyword",
				"ignore_above": 256
			  }
			}
		  },
		  "output": {
			"type": "text",
			"fields": {
			  "keyword": {
				"type": "keyword",
				"ignore_above": 2048
			  }
			}
		  },
		  "output_fields": {
			"properties": {
			  "container_info": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "container_mounts": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "container_start": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_arg_cmd": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_arg_fd": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_arg_filename": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_arg_flags": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_arg_linkpath": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_arg_mode": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_arg_name": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_arg_newpath": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_arg_oldpath": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_arg_path": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_arg_target": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_arg_uid": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_args": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_res": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "evt_type": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "fd_cip_name": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "fd_lip_name": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "fd_lport": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "fd_name": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "fd_nameraw": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "fd_rip": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "fd_rip_name": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "fd_rport": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "fd_sip": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "fd_sip_name": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "fd_sport": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "fd_type": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "group_gid": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "group_name": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "jevt_obj": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "jevt_value": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_auth_decision": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_auth_reason": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_req_binding": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_req_configmap": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_req_pod": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_req_role": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_req_service": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_resp_name": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_response_code": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_response_reason": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_target_name": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_target_namespace": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_target_resource": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_target_subresource": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_uri": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_uri_param": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_user_name": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "ka_verb": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_aexepath": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_aname": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_args": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_cmdline": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_cwd": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_env": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_exe": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_exepath": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_name": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_pcmdline": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_pexe": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_pexepath": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_pname": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_sname": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "proc_tty": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "test_dash": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "test_slash": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "thread_cap": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "user_loginname": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "user_loginuid": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "user_name": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  },
			  "user_uid": {
				"type": "text",
				"fields": {
				  "keyword": {
					"type": "keyword",
					"ignore_above": 256
				  }
				}
			  }
			}
		  },
		  "priority": {
			"type": "text",
			"fields": {
			  "keyword": {
				"type": "keyword",
				"ignore_above": 256
			  }
			}
		  },
		  "rule": {
			"type": "text",
			"fields": {
			  "keyword": {
				"type": "keyword",
				"ignore_above": 256
			  }
			}
		  },
		  "source": {
			"type": "text",
			"fields": {
			  "keyword": {
				"type": "keyword",
				"ignore_above": 256
			  }
			}
		  },
		  "tags": {
			"type": "text",
			"fields": {
			  "keyword": {
				"type": "keyword",
				"ignore_above": 256
			  }
			}
		  },
		  "time": {
			"type": "date"
		  },
		  "uuid": {
			"type": "text",
			"fields": {
			  "keyword": {
				"type": "keyword",
				"ignore_above": 256
			  }
			}
		  }
		}
	  }
	}
  }
`
