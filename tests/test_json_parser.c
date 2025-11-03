#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <json-c/json.h>

// Mock structures (same as your eBPF program)
struct rule_key {
    uint32_t rule_id;
};

struct rule_value {
    uint32_t protocol_num;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t tcp_flags;
    uint32_t action;
};

// Simulate BPF map with simple array
#define MAX_RULES 10000
struct rule_value rules_db[MAX_RULES] = {0};

// Mock map update function
int mock_bpf_map_update(int rule_id, struct rule_value *value) {
    if (rule_id >= MAX_RULES) return -1;
    
    rules_db[rule_id] = *value;
    printf("✓ Stored rule %d: proto=%d, src_ip=%08x, dst_ip=%08x\n",
           rule_id, value->protocol_num, value->src_ip, value->dst_ip);
    return 0;
}

// Your JSON parsing logic (same as snort_loader.c)
int load_rules_from_json(const char *json_file) {
    FILE *fp = fopen(json_file, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open %s\n", json_file);
        return -1;
    }
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *json_str = malloc(fsize + 1);
    fread(json_str, 1, fsize, fp);
    fclose(fp);
    json_str[fsize] = 0;
    
    // Parse JSON array
    struct json_object *parsed_json = json_tokener_parse(json_str);
    if (!parsed_json) {
        fprintf(stderr, "JSON parsing failed\n");
        return -1;
    }
    
    int n_rules = json_object_array_length(parsed_json);
    printf("=== Loading %d rules ===\n", n_rules);
    
    for (int i = 0; i < n_rules; i++) {
        struct json_object *rule_obj = json_object_array_get_idx(parsed_json, i);
        
        struct rule_value value = {0};
        
        // Extract protocol_num
        struct json_object *proto_obj;
        if (json_object_object_get_ex(rule_obj, "protocol_num", &proto_obj)) {
            value.protocol_num = json_object_get_int(proto_obj);
        }
        
        // Extract and convert src_ip string to uint32
        struct json_object *src_ip_obj;
        if (json_object_object_get_ex(rule_obj, "src_ip", &src_ip_obj)) {
            const char *src_ip_str = json_object_get_string(src_ip_obj);
            if (strcmp(src_ip_str, "any") != 0) {
                inet_pton(AF_INET, src_ip_str, &value.src_ip);
            }
        }
        
        // Extract dst_ip
        struct json_object *dst_ip_obj;
        if (json_object_object_get_ex(rule_obj, "dst_ip", &dst_ip_obj)) {
            const char *dst_ip_str = json_object_get_string(dst_ip_obj);
            if (strcmp(dst_ip_str, "any") != 0) {
                inet_pton(AF_INET, dst_ip_str, &value.dst_ip);
            }
        }
        
        // Extract ports (simplified - extend based on your format)
        struct json_object *dst_port_obj;
        if (json_object_object_get_ex(rule_obj, "dst_port", &dst_port_obj)) {
            struct json_object *port_obj;
            if (json_object_object_get_ex(dst_port_obj, "port", &port_obj)) {
                value.dst_port = json_object_get_int(port_obj);
            }
        }
        
        // Extract action (alert=1, drop=2)
        struct json_object *action_obj;
        if (json_object_object_get_ex(rule_obj, "action", &action_obj)) {
            const char *action_str = json_object_get_string(action_obj);
            if (strcmp(action_str, "alert") == 0) {
                value.action = 1;
            } else if (strcmp(action_str, "drop") == 0) {
                value.action = 2;
            }
        }
        
        // Simulate BPF map update
        mock_bpf_map_update(i, &value);
    }
    
    free(json_str);
    json_object_put(parsed_json);
    
    printf("\n=== Verification: First 3 Rules ===\n");
    for (int i = 0; i < 3 && i < n_rules; i++) {
        printf("Rule %d: proto=%d, action=%d, dst_port=%d\n",
               i, rules_db[i].protocol_num, rules_db[i].action, 
               rules_db[i].dst_port);
    }
    
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <json_file>\n", argv[0]);
        return 1;
    }
    
    int result = load_rules_from_json(argv[1]);
    
    if (result == 0) {
        printf("\n✅ JSON parsing and mock map population successful!\n");
    } else {
        printf("\n❌ Failed to parse JSON\n");
    }
    
    return result;
}
