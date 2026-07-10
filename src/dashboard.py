'''
dashboard.py
- layout and callback for real time anomaly dashboard
'''

#-----imports-----
import dash
from dash import dcc, html, dash_table, Input, Output
import dash_bootstrap_components as dbc
import plotly.graph_objects as go

import pandas as pd
from src.database import get_recent_anomalies, get_threat_summary, initialise_database
from src.logger import get_logger
from datetime import datetime, timezone

#setup logger
logger = get_logger(__name__)

#-----creating the app-----
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])

#needed for deployment on Render
server = app.server

#-----initialise database on startup-----
initialise_database()

#dbc container is a full width wrapper.
#fluid = true makes it stretch edge to edge
app.layout = dbc.Container([
    #-----section 1 - header row-----
    dbc.Row([
        dbc.Col([
            html.H1("Real-Time Anomaly Detection Dashboard",
                    className="text-danger fw-bold"),
            html.P("Live network traffic analysis powered by Isolation Forest",
                   className="text-muted"),
            #id = "last updated" - callback will update this with current time every 2 seconds
            html.P(id="last-updated", className="text-muted small")
        ])
    ], className="my-3"),

    #-----section 2 - metric cards-----
    dbc.Row([
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H4("Total Anomalies", className="card-title text-muted small"),
                html.H2(id="total-count", className="text-white fw-bold")
            ])
        ], color="dark", outline=True), width=3),
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H4("Critical Count", className="card-title text-muted small"),
                html.H2(id="critical-count", className="text-white fw-bold")
            ])
        ], color="dark", outline=True), width=3),
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H4("Medium Count", className="card-title text-muted small"),
                html.H2(id="medium-count", className="text-white fw-bold")
            ])
        ], color="dark", outline=True), width=3),
        dbc.Col(dbc.Card([
            dbc.CardBody([
                html.H4("Low Count", className="card-title text-muted small"),
                html.H2(id="low-count", className="text-white fw-bold")
            ])
        ], color="dark", outline=True), width=3),
    ], className="mb-3"),

    #-----section 3 - graph-----
    dbc.Row([
        dbc.Col([
            dcc.Graph(id="threat-graph")
        ])
    ], className="mb-3"),

    #-----section 4- table-----
    dbc.Row([
        dbc.Col([
            html.H5("Flagged Packets", className="text-danger"),
            dash_table.DataTable(
                id="anomaly-table",
                columns=[
                    {"name": "Timestamp", "id": "timestamp"},
                    {"name": "IP", "id": "ip"},
                    {"name": "Port", "id": "port"},
                    {"name": "Port Context", "id": "port_context"},
                    {"name": "Score", "id": "score"},
                    {"name": "Threat Level", "id": "threat_level"},
                    {"name": "Action", "id": "action"},
                ],
                style_header={"backgroundColor": "#222", "color": "white", "fontWeight": "bold"},
                style_cell={"backgroundColor": "#111", "color": "white", "border": "1px solid #333"},
                style_data_conditional=[
                    {"if": {"filter_query": '{threat_level} = "Critical"'},
                     "backgroundColor": "#3D0000", "color": "#FF4444"},
                    {"if": {"filter_query": '{threat_level} = "Medium"'},
                     "backgroundColor": "#3D2000", "color": "#FFA500"},
                    {"if": {"filter_query": '{threat_level} = "Low"'},
                     "backgroundColor": "#3D3D00", "color": "#FFD700"},
                ],
                page_size=15,
                sort_action="native",
            )
        ])
    ]),

    #-----section 5 - hidden interval-----
    dcc.Interval(id="interval", interval=2000, n_intervals=0)
], fluid = True)


#-----structuring the callback-----
@app.callback(
    Output("last-updated", "children"),
    Output("total-count", "children"),
    Output("critical-count", "children"),
    Output("medium-count", "children"),
    Output("low-count", "children"),
    Output("threat-graph", "figure"),
    Output("anomaly-table", "data"),
    Input("interval", "n_intervals")
)
def update_dashboard(n):
    # everything here runs every 2 seconds
    recent = get_recent_anomalies()
    summary = get_threat_summary()

    #last updated timestamp
    last_updated = f"Last updated: {datetime.now(timezone.utc).strftime('%H:%M:%S')} UTC"

    #calculate metric card values
    total = sum(s["count"] for s in summary)
    critical = next((s["count"] for s in summary if s["threat_level"] == "Critical"), 0)
    medium = next((s["count"] for s in summary if s["threat_level"] == "Medium"), 0)
    low = next((s["count"] for s in summary if s["threat_level"] == "Low"), 0)
    
    #build graph figure — using plain dict instead of go. Figure for JSON serialisation
    if recent:
        timestamps = [str(r["timestamp"]) for r in recent]
        scores = [float(r["score"]) for r in recent]
        fig = {
            "data": [{
                "x": timestamps,
                "y": scores,
                "type": "scatter",
                "mode": "lines+markers",
                "line": {"color": "#FF4444"},
                "name": "Threat Score"
            }],
            "layout": {
                "title": "Live Threat Scores",
                "paper_bgcolor": "#111",
                "plot_bgcolor": "#111",
                "font": {"color": "white"},
                "xaxis": {"title": "Time"},
                "yaxis": {"title": "Threat Score", "range": [0, 1]}
            }
        }
    else:
        fig = {
            "data": [],
            "layout": {
                "title": "No Data yet",
                "paper_bgcolor": "#111",
                "plot_bgcolor": "#111",
                "font": {"color": "white"}
            }
        }
    
    #format table data
    #format table data — convert all values to JSON serialisable types
    table_data = [
        {
            "timestamp": str(r["timestamp"]),
            "ip":           str(r["ip"]),
            "port":         int(r["port"]),
            "port_context": str(r["port_context"]),
            "score":        float(r["score"]),
            "threat_level": str(r["threat_level"]),
            "action":       str(r["action"])
        }
        for r in recent
    ]
    
    #return all output in same order as decorators
    return last_updated, total, critical, medium, low, fig, table_data

#-----run app-----
if __name__ == "__main__":
    app.run(debug=True)
