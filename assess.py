def assess_ICMP(data:dict,ip:str) -> dict:
    threat = {
        ip:{
            "is_flagged":False,
            "points":0,
            "risk_factors":[]
        }
    }
    # Getting how much unique ip the mahcine pinged
    ICMP_targets_count = len(data["IPs"][ip]["ICMP_targets"])

    # we have the first 8 pings are free no flag poitns asigned if we go above thershold we add 2 points for each ip possible ping sweep
    result = max(0,((ICMP_targets_count - 8) * 2))
    if result > 0:
        threat[ip]["points"] += result
        threat[ip]["risk_factors"].append("excessive ping sweep")

    # we have the first 6 pings are free anythig above we strt adding two points because of possibel DDos
    result = max(0,((data["IPs"][ip]["unreachable_count"] - 6) * 2))
    if result > 0:
        threat[ip]["points"] += result
        threat[ip]["risk_factors"].append("possible DDos attack")

    # if we detect redirect icmp red flag
    if data["IPs"][ip]["redirect_detected"]:
        threat[ip]["points"] += 15
        threat[ip]["risk_factors"].append("redirect attack")
    

    if threat[ip]["points"] >= 15:
        threat[ip]["is_flagged"] = True

    return threat
